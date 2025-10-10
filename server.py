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

def init_db():
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute('CREATE TABLE IF NOT EXISTS users (login TEXT PRIMARY KEY, password TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, login TEXT, expires TIMESTAMP)')
    
    # Add indexes for optimization
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_login ON sessions(login)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_users_login_password ON users(login, password)')
    
    conn.close()

def clean_sessions():
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute('DELETE FROM sessions WHERE expires < ?', (datetime.now(),))
    conn.commit()
    conn.close()

@app.middleware("http")
async def cleanup_middleware(request, call_next):
    clean_sessions()
    response = await call_next(request)
    return response

@app.post('/register')
def register(request: RegisterRequest):
    if request.type != 'reg':
        raise HTTPException(status_code=400, detail='Invalid request type')
    
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        conn.execute('INSERT INTO users (login, password) VALUES (?, ?)', (request.login, request.password))
        
        session_id = str(uuid.uuid4())
        expires = datetime.now() + timedelta(minutes=30)
        conn.execute('INSERT INTO sessions (session_id, login, expires) VALUES (?, ?, ?)', 
                    (session_id, request.login, expires))
        conn.commit()
        
        return {'session_id': session_id}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail='User already registered')
    finally:
        conn.close()

@app.post('/login')
def login(request: LoginRequest):
    if request.type != 'login':
        raise HTTPException(status_code=400, detail='Invalid request type')
    
    conn = sqlite3.connect('polzovateli.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        user = conn.execute('SELECT * FROM users WHERE login = ? AND password = ?', 
                           (request.login, request.password)).fetchone()
        
        if user:
            # Delete existing sessions for this login
            conn.execute('DELETE FROM sessions WHERE login = ?', (request.login,))
            
            # Create new session
            session_id = str(uuid.uuid4())
            expires = datetime.now() + timedelta(minutes=30)
            conn.execute('INSERT INTO sessions (session_id, login, expires) VALUES (?, ?, ?)', 
                        (session_id, request.login, expires))
            conn.commit()
            return {'session_id': session_id}
        else:
            raise HTTPException(status_code=401, detail='Invalid login or password')
    finally:
        conn.close()

if __name__ == '__main__':
    import uvicorn
    init_db()
    uvicorn.run(app, host='0.0.0.0', port=8000)
