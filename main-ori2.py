import os
import time
import base64
import struct
import json
import re
import secrets
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
import nacl.secret
from curl_cffi import requests as curl_requests
import redis
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============ CONFIGURATION ============
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "true").lower() == "true"
API_KEYS = os.getenv("API_KEYS", "").split(",") if os.getenv("API_KEYS") else []

# Generate a default API key if none provided
if ENABLE_AUTH and not API_KEYS:
    default_key = secrets.token_urlsafe(32)
    API_KEYS = [default_key]
    print(f"⚠️ No API keys found. Using generated key: {default_key}")

# Rate limiting
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "1000"))

# Redis configuration
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_SSL = os.getenv("REDIS_SSL", "true").lower() == "true"

ENVIRONMENT = os.getenv("ENVIRONMENT", "production")

# Allowed domains - allow localhost for testing
ALLOWED_DOMAINS = [
    r"^https?://([a-zA-Z0-9-]+\.)*cinehub\.top$",
    r"^https?://([a-zA-Z0-9-]+\.)*vidfy\.sbs$",
    r"^https?://localhost(:\d+)?$",
    r"^https?://127\.0\.0\.1(:\d+)?$",
]

ALLOWED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in ALLOWED_DOMAINS]

# Encryption settings
KEY_HEX = os.getenv("ENCRYPTION_KEY", "c75136c5668bbfe65a7ecad431a745db68b5f381555b38d8f6c699449cf11fcd")
KEY = bytes.fromhex(KEY_HEX)
BOX = nacl.secret.SecretBox(KEY)
NONCE = bytes(24)

# Default headers for curl requests
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    'Origin': 'https://vidlink.pro',
    'Referer': 'https://vidlink.pro/'
}

security = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ============ REDIS CONNECTION ============
redis_client = None

def init_redis():
    global redis_client
    try:
        connection_params = {
            'host': REDIS_HOST,
            'port': REDIS_PORT,
            'password': REDIS_PASSWORD,
            'decode_responses': True,
            'socket_connect_timeout': 5,
            'socket_keepalive': True,
        }
        if REDIS_SSL:
            connection_params['ssl'] = True
        redis_client = redis.Redis(**connection_params)
        redis_client.ping()
        print("✅ Connected to Redis successfully")
    except Exception as e:
        print(f"⚠️ Redis connection failed: {e}")
        redis_client = None

# ============ FASTAPI APP ============
app = FastAPI(title="VidLink Pro API", docs_url=None, redoc_url=None)

# ============ MIDDLEWARES ============
@app.middleware("http")
async def restrict_domains(request: Request, call_next):
    if request.url.path == "/":
        return await call_next(request)
    
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    
    is_allowed = False
    for header in [origin, referer]:
        if header:
            for pattern in ALLOWED_PATTERNS:
                if pattern.match(header):
                    is_allowed = True
                    break
        if is_allowed:
            break
    
    if not is_allowed and origin and referer:
        return JSONResponse(
            status_code=403,
            content={"error": "Access Denied"}
        )
    
    return await call_next(request)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if not RATE_LIMIT_ENABLED or request.url.path == "/":
        return await call_next(request)
    
    client_ip = request.client.host
    current_minute = int(time.time() / 60)
    minute_key = f"rate_limit:{client_ip}:minute:{current_minute}"
    
    if redis_client:
        try:
            minute_count = redis_client.get(minute_key)
            if minute_count and int(minute_count) >= RATE_LIMIT_PER_MINUTE:
                return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})
            redis_client.incr(minute_key)
            redis_client.expire(minute_key, 60)
        except Exception as e:
            print(f"Rate limit error: {e}")
    
    return await call_next(request)

# ============ AUTHENTICATION ============
async def verify_api_key(
    bearer_auth: HTTPAuthorizationCredentials = Depends(security),
    api_key_header_value: str = Depends(api_key_header)
):
    if not ENABLE_AUTH:
        return None
    
    api_key = None
    if bearer_auth:
        api_key = bearer_auth.credentials
    if not api_key and api_key_header_value:
        api_key = api_key_header_value
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if api_key not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return api_key

# ============ CORS CONFIGURATION ============
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for maximum compatibility
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ HELPER FUNCTIONS ============
def encrypt_token(media_id: str):
    timestamp = int(time.time() + 480)
    message = media_id.encode("utf-8") + struct.pack(">Q", timestamp)
    encrypted = BOX.encrypt(message, NONCE)
    full_payload = NONCE + encrypted.ciphertext
    return base64.urlsafe_b64encode(full_payload).decode("utf-8").rstrip("=")

# ============ API ENDPOINTS ============
@app.get("/", response_class=HTMLResponse)
async def home():
    # Your existing HTML response (keeping it simple for brevity)
    return """
    <!DOCTYPE html>
    <html>
    <head><title>VidLink Pro API</title></head>
    <body>
        <h1>VidLink Pro API</h1>
        <p>API is running. Use /movie/{id} or /tv/{id}/{season}/{episode}</p>
    </body>
    </html>
    """

@app.get("/movie/{movie_id}")
async def get_movie(
    movie_id: str, 
    api_key: str = Depends(verify_api_key)
):
    """Get movie stream sources - Returns EXACT same response as original"""
    token = encrypt_token(movie_id)
    url = f"https://vidlink.pro/api/b/movie/{token}?multiLang=1"
    
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110", timeout=30)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"VidLink returned {response.status_code}")
        
        data = response.json()
        
        # Return the EXACT same response as your original code
        if not data:
            raise HTTPException(status_code=404, detail="No source found")
        
        return data  # Direct return, no modification
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tv/{tv_id}/{season}/{episode}")
async def get_tv(
    tv_id: str, 
    season: int, 
    episode: int,
    api_key: str = Depends(verify_api_key)
):
    """Get TV episode stream sources - Returns EXACT same response as original"""
    token = encrypt_token(tv_id)
    url = f"https://vidlink.pro/api/b/tv/{token}/{season}/{episode}?multiLang=1"
    
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110", timeout=30)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"VidLink returned {response.status_code}")
        
        data = response.json()
        
        if not data:
            raise HTTPException(status_code=404, detail="No source found")
        
        return data  # Direct return, no modification
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": time.time()}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)