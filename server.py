from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import FileResponse
from pydantic import BaseModel
import sqlite3
import uuid
import os
from datetime import datetime, timedelta
from pathlib import Path

sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
sqlite3.register_converter("TIMESTAMP", lambda b: datetime.fromisoformat(b.decode()))

app = FastAPI()

class RegisterRequest(BaseModel):
    login: str
    password: str

class LoginRequest(BaseModel):
    login: str
    password: str

class ListRequest(BaseModel):
    session_id: str
    path: str

class LogoutRequest(BaseModel):
    session_id: str

class DeleteRequest(BaseModel):
    session_id: str
    path: str

def init_db():
    conn = sqlite3.connect('users.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute('CREATE TABLE IF NOT EXISTS users (login TEXT PRIMARY KEY, password TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, login TEXT, expires TIMESTAMP)')
    
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_login ON sessions(login)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_users_login_password ON users(login, password)')
    
    conn.close()
    
    if not os.path.exists('users'):
        os.makedirs('users')

def clean_sessions():
    conn = sqlite3.connect('users.db', detect_types=sqlite3.PARSE_DECLTYPES)
    conn.execute('DELETE FROM sessions WHERE expires < ?', (datetime.now(),))
    conn.commit()
    conn.close()

def validate_session(session_id: str):
    conn = sqlite3.connect('users.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        session = conn.execute('SELECT login FROM sessions WHERE session_id = ? AND expires > ?', 
                              (session_id, datetime.now())).fetchone()
        if session:
            return session[0]
        return None
    finally:
        conn.close()

@app.middleware("http")
async def cleanup_middleware(request, call_next):
    clean_sessions()
    response = await call_next(request)
    return response

@app.post('/register')
def register(request: RegisterRequest):
    conn = sqlite3.connect('users.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        conn.execute('INSERT INTO users (login, password) VALUES (?, ?)', (request.login, request.password))
        
        user_dir = os.path.join('users', request.login)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        
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
    conn = sqlite3.connect('users.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        user = conn.execute('SELECT * FROM users WHERE login = ? AND password = ?', 
                           (request.login, request.password)).fetchone()
        
        if user:
            conn.execute('DELETE FROM sessions WHERE login = ?', (request.login,))
            
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

@app.post('/ls')
def list_files(request: ListRequest):
    login = validate_session(request.session_id)
    if not login:
        raise HTTPException(status_code=403, detail='Invalid session')
    
    safe_login = ''.join(c for c in login if c.isalnum() or c in '_-')
    user_dir = os.path.join('users', safe_login)
    
    if not os.path.exists(user_dir):
        os.makedirs(user_dir, exist_ok=True)
        return {'files': []}
    
    try:
        files = [f for f in os.listdir(user_dir) if os.path.isfile(os.path.join(user_dir, f))]
        return {'files': files}
    except OSError:
        raise HTTPException(status_code=500, detail='Error accessing user directory')

@app.post('/logout')
def logout(request: LogoutRequest):
    conn = sqlite3.connect('users.db', detect_types=sqlite3.PARSE_DECLTYPES)
    try:
        session = conn.execute('SELECT * FROM sessions WHERE session_id = ?', (request.session_id,)).fetchone()
        if not session:
            return {'status': 'Session not found'}
        
        conn.execute('DELETE FROM sessions WHERE session_id = ?', (request.session_id,))
        conn.commit()
        return {'status': 'OK'}
    except Exception as e:
        return {'status': str(e)}
    finally:
        conn.close()

@app.post('/del')
def delete_file(request: DeleteRequest):
    login = validate_session(request.session_id)
    if not login:
        raise HTTPException(status_code=403, detail='Invalid session')
    
    safe_login = ''.join(c for c in login if c.isalnum() or c in '_-')
    safe_filename = os.path.basename(request.path)
    
    if not safe_filename or '..' in safe_filename:
        return {'status': 'Invalid filename'}
    
    try:
        file_path = os.path.join('users', safe_login, safe_filename)
        if not os.path.abspath(file_path).startswith(os.path.abspath(os.path.join('users', safe_login))):
            return {'status': 'Access denied'}
        
        if not os.path.exists(file_path):
            return {'status': 'File not found'}
        
        os.remove(file_path)
        return {'status': 'OK'}
    except OSError:
        return {'status': 'Error deleting file'}

@app.post('/upload')
async def upload_file(session_id: str = Form(...), file: UploadFile = File(...)):
    login = validate_session(session_id)
    if not login:
        raise HTTPException(status_code=403, detail='Invalid session')
    
    safe_login = ''.join(c for c in login if c.isalnum() or c in '_-')
    safe_filename = os.path.basename(file.filename or 'unnamed')
    
    if not safe_filename or '..' in safe_filename:
        return {'status': 'Invalid filename'}
    
    try:
        user_dir = os.path.join('users', safe_login)
        if not os.path.exists(user_dir):
            os.makedirs(user_dir, exist_ok=True)
        
        file_path = os.path.join(user_dir, safe_filename)
        if not os.path.abspath(file_path).startswith(os.path.abspath(user_dir)):
            return {'status': 'Access denied'}
        
        with open(file_path, 'wb') as f:
            content = await file.read()
            f.write(content)
        
        return {'status': 'OK'}
    except OSError:
        return {'status': 'Error uploading file'}

@app.get('/download/{filename}')
def download_file(filename: str, session_id: str):
    login = validate_session(session_id)
    if not login:
        raise HTTPException(status_code=403, detail='Invalid session')
    
    safe_login = ''.join(c for c in login if c.isalnum() or c in '_-')
    safe_filename = os.path.basename(filename)
    
    if not safe_filename or '..' in safe_filename:
        raise HTTPException(status_code=400, detail='Invalid filename')
    
    file_path = os.path.join('users', safe_login, safe_filename)
    if not os.path.abspath(file_path).startswith(os.path.abspath(os.path.join('users', safe_login))):
        raise HTTPException(status_code=403, detail='Access denied')
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail='File not found')
    
    return FileResponse(file_path, filename=safe_filename)

if __name__ == '__main__':
    import uvicorn
    init_db()
    uvicorn.run(app, host='127.0.0.1', port=8000)