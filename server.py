from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import uuid
from datetime import datetime, timedelta

sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
sqlite3.register_converter("TIMESTAMP", lambda b: datetime.fromisoformat(b.decode()))

app = FastAPI()

class RegisterRequest(BaseModel):
    type: str
    login: str
    password: str

class LoginRequest(BaseModel):
    type: str
    login: str
    password: str

def init_baza():
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute('CREATE TABLE IF NOT EXISTS users (login TEXT PRIMARY KEY, password TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, login TEXT, expires TIMESTAMP)')
    
    # Добавляем индексы для оптимизации
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_login ON sessions(login)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_users_login_password ON users(login, password)')
    
    conn.close()

def ochistit_sessii():
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute('DELETE FROM sessions WHERE expires < ?', (datetime.now(),))
    conn.commit()
    conn.close()

@app.middleware("http")
async def cleanup_middleware(request, call_next):
    ochistit_sessii()
    response = await call_next(request)
    return response

@app.post('/register')
def registratsiya(request: RegisterRequest):
    if request.type != 'reg':
        raise HTTPException(status_code=400, detail='Неверный тип запроса')
    
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        conn.execute('INSERT INTO users (login, password) VALUES (?, ?)', (request.login, request.password))
        
        id_sessii = str(uuid.uuid4())
        vremya_istecheniya = datetime.now() + timedelta(minutes=30)
        conn.execute('INSERT INTO sessions (session_id, login, expires) VALUES (?, ?, ?)', 
                    (id_sessii, request.login, vremya_istecheniya))
        conn.commit()
        
        return {'session_id': id_sessii}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail='Пользователь уже зарегистрирован')
    finally:
        conn.close()

@app.post('/login')
def vhod(request: LoginRequest):
    if request.type != 'login':
        raise HTTPException(status_code=400, detail='Неверный тип запроса')
    
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        user = conn.execute('SELECT * FROM users WHERE login = ? AND password = ?', 
                           (request.login, request.password)).fetchone()
        
        if user:
            # Удаляем существующие сессии для этого логина
            conn.execute('DELETE FROM sessions WHERE login = ?', (request.login,))
            
            # Создаем новую сессию
            id_sessii = str(uuid.uuid4())
            vremya_istecheniya = datetime.now() + timedelta(minutes=30)
            conn.execute('INSERT INTO sessions (session_id, login, expires) VALUES (?, ?, ?)', 
                        (id_sessii, request.login, vremya_istecheniya))
            conn.commit()
            return {'session_id': id_sessii}
        else:
            raise HTTPException(status_code=401, detail='Неверный логин или пароль')
    finally:
        conn.close()

if __name__ == '__main__':
    import uvicorn
    init_baza()
    uvicorn.run(app, host='0.0.0.0', port=8000)