from fastapi import FastAPI, HTTPException, File, UploadFile, Form, Depends
from fastapi.responses import FileResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from contextlib import asynccontextmanager
import redis.asyncio as redis
from pydantic import BaseModel
import sqlite3
import uuid
import os
from datetime import datetime, timedelta
from pathlib import Path
import argparse

sqlite3.register_adapter(datetime, lambda dt: dt.isoformat())
sqlite3.register_converter("TIMESTAMP", lambda b: datetime.fromisoformat(b.decode()))

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

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    redis_connection = redis.from_url("redis://localhost:6379", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(redis_connection)
    
    yield
    
    await redis_connection.close()

app = FastAPI(lifespan=lifespan)

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

# --- Routes ---

# Group 1: 10 requests per minute
@app.post('/register', dependencies=[Depends(RateLimiter(times=10, seconds=60))])
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

@app.post('/login', dependencies=[Depends(RateLimiter(times=10, seconds=60))])
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

@app.post('/logout', dependencies=[Depends(RateLimiter(times=10, seconds=60))])
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

# Group 2: 500 requests per minute
@app.post('/ls', dependencies=[Depends(RateLimiter(times=500, seconds=60))])
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

@app.get('/fileInfo/{filename}', dependencies=[Depends(RateLimiter(times=500, seconds=60))])
def get_file_info(filename: str, session_id: str):
    login = validate_session(session_id)
    if not login:
        return {'status': 'Invalid session'}
    
    safe_login = ''.join(c for c in login if c.isalnum() or c in '_-')
    safe_filename = os.path.basename(filename)
    
    if not safe_filename or '..' in safe_filename:
        return {'status': 'Invalid filename'}
    
    user_dir = os.path.join('users', safe_login)
    file_path = os.path.join(user_dir, safe_filename)
    
    try:
        if not os.path.abspath(file_path).startswith(os.path.abspath(user_dir)):
            return {'status': 'Access denied'}
        
        if not os.path.exists(file_path):
            return {'status': 'File not found'}
            
        stats = os.stat(file_path)
        
        # Helper to format timestamp
        def format_ts(ts):
            return datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H-%M-%S')
            
        uploaded_str = format_ts(stats.st_mtime)
        
        file_info = {
            "name": safe_filename,
            "uploaded": uploaded_str,
            "size": stats.st_size
        }
            
        return {
            "status": "OK",
            "fileInfo": file_info
        }
        
    except OSError:
        return {'status': 'Error reading file info'}

# Group 3: 100 requests per minute
@app.post('/del', dependencies=[Depends(RateLimiter(times=100, seconds=60))])
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

@app.post('/upload', dependencies=[Depends(RateLimiter(times=100, seconds=60))])
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

@app.get('/download/{filename}', dependencies=[Depends(RateLimiter(times=100, seconds=60))])
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
    
    parser = argparse.ArgumentParser(description="Start the FastAPI server")
    parser.add_argument("host", help="Host IP address (e.g. 127.0.0.1)")
    parser.add_argument("port", type=int, help="Port number (e.g. 8000)")
    parser.add_argument("--ssl-public-key", help="Path to SSL public key (certificate)")
    parser.add_argument("--ssl-private-key", help="Path to SSL private key")
    
    args = parser.parse_args()
    
    uvicorn_kwargs = {
        "host": args.host,
        "port": args.port,
    }
    
    if args.ssl_public_key and args.ssl_private_key:
        if os.path.exists(args.ssl_public_key) and os.path.exists(args.ssl_private_key):
            uvicorn_kwargs["ssl_certfile"] = args.ssl_public_key
            uvicorn_kwargs["ssl_keyfile"] = args.ssl_private_key
            print(f"Starting with SSL. Cert: {args.ssl_public_key}")
        else:
            print("Error: One or both SSL key files not found.")
            exit(1)
            
    # init_db is now called in lifespan
    uvicorn.run(app, **uvicorn_kwargs)