import os
import time
import base64
import struct
import json
import re
import secrets  # ← ADD THIS IMPORT
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import nacl.secret
from curl_cffi import requests as curl_requests
import redis
import jwt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ============ CONFIGURATION ============
# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

# Generate a secure JWT secret if not provided
if JWT_SECRET_KEY == secrets.token_urlsafe(32):
    print(f"⚠️ JWT_SECRET_KEY not set. Using generated key. Please set in .env for production!")
    print(f"Generated key: {JWT_SECRET_KEY}")

# Rate limiting
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))
RATE_LIMIT_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "1000"))

# Redis configuration (optional - for token blacklist only)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_SSL = os.getenv("REDIS_SSL", "true").lower() == "true"

ENVIRONMENT = os.getenv("ENVIRONMENT", "production")

# Allowed domains - optional additional security
ALLOWED_DOMAINS = [
    r"^https?://([a-zA-Z0-9-]+\.)*cinehub\.top$",
    r"^https?://([a-zA-Z0-9-]+\.)*vidfy\.sbs$",
     r"^https?://streamx\.cinehub\.top$",      
    r"^https?://player\.vidfy\.sbs$", 
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

# ============ REDIS CONNECTION (for token blacklist) ============
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
        print("✅ Connected to Redis successfully (for token blacklist)")
        return True
    except Exception as e:
        print(f"⚠️ Redis connection failed: {e}")
        print("⚠️ Token revocation will be disabled")
        redis_client = None
        return False

# ============ JWT FUNCTIONS ============
def create_jwt_token(client_id: str = None) -> dict:
    """Create a new JWT token"""
    if client_id is None:
        client_id = secrets.token_urlsafe(16)
    
    payload = {
        "client_id": client_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        "jti": secrets.token_urlsafe(16)  # Unique token ID for revocation
    }
    
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRY_HOURS * 3600,
        "expires_at": (datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)).isoformat()
    }

def verify_jwt_token(token: str) -> dict:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(
            token, 
            JWT_SECRET_KEY, 
            algorithms=[JWT_ALGORITHM]
        )
        
        # Check if token is blacklisted (revoked)
        if redis_client and is_token_revoked(payload.get("jti")):
            raise jwt.InvalidTokenError("Token has been revoked")
        
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

def revoke_jwt_token(jti: str):
    """Revoke a JWT token by adding to blacklist"""
    if redis_client:
        # Add to blacklist with expiry same as token
        redis_client.setex(f"revoked:{jti}", JWT_EXPIRY_HOURS * 3600, "1")
        return True
    return False

def is_token_revoked(jti: str) -> bool:
    """Check if token is revoked"""
    if redis_client:
        return redis_client.exists(f"revoked:{jti}") > 0
    return False

# ============ FASTAPI APP ============
app = FastAPI(title="VidLink Pro API", docs_url=None, redoc_url=None)

# ============ MIDDLEWARES ============
@app.middleware("http")
async def restrict_domains(request: Request, call_next):
    """Optional domain restriction (additional security layer)"""
    if request.url.path == "/" or request.url.path == "/api/token":
        return await call_next(request)
    
    # Domain restriction is optional - you can enable/disable as needed
    if ENVIRONMENT == "production":
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
        
        # Only block if both origin and referer are present and not allowed
        if origin and referer and not is_allowed:
            print(f"❌ Blocked request from: origin={origin}, referer={referer}")
            return JSONResponse(
                status_code=403,
                content={"error": "Access Denied", "message": "Unauthorized domain"}
            )
    
    return await call_next(request)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware using Redis"""
    if not RATE_LIMIT_ENABLED or request.url.path == "/" or request.url.path == "/api/token":
        return await call_next(request)
    
    client_ip = request.client.host
    current_minute = int(time.time() / 60)
    current_hour = int(time.time() / 3600)
    
    minute_key = f"rate_limit:{client_ip}:minute:{current_minute}"
    hour_key = f"rate_limit:{client_ip}:hour:{current_hour}"
    
    if redis_client:
        try:
            # Check minute limit
            minute_count = redis_client.get(minute_key)
            if minute_count and int(minute_count) >= RATE_LIMIT_PER_MINUTE:
                return JSONResponse(
                    status_code=429, 
                    content={"error": "Rate limit exceeded. Please try again later."}
                )
            
            # Check hour limit
            hour_count = redis_client.get(hour_key)
            if hour_count and int(hour_count) >= RATE_LIMIT_PER_HOUR:
                return JSONResponse(
                    status_code=429, 
                    content={"error": "Hourly rate limit exceeded."}
                )
            
            redis_client.incr(minute_key)
            redis_client.expire(minute_key, 60)
            redis_client.incr(hour_key)
            redis_client.expire(hour_key, 3600)
            
        except Exception as e:
            print(f"Rate limit error: {e}")
    
    return await call_next(request)

# ============ JWT AUTHENTICATION ============
async def verify_jwt(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Verify JWT token from Bearer header"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token required. Provide via 'Authorization: Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    return payload

# ============ CORS CONFIGURATION ============
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cinehub.top",
        "https://*.cinehub.top",
        "https://streamx.cinehub.top",
        "https://vidfy.sbs",
        "https://*.vidfy.sbs",
        "https://player.vidfy.sbs",
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,
)

# ============ HELPER FUNCTIONS ============
def encrypt_token(media_id: str):
    timestamp = int(time.time() + 480)
    message = media_id.encode("utf-8") + struct.pack(">Q", timestamp)
    encrypted = BOX.encrypt(message, NONCE)
    full_payload = NONCE + encrypted.ciphertext
    return base64.urlsafe_b64encode(full_payload).decode("utf-8").rstrip("=")

# ============ LIFESPAN MANAGEMENT ============
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_redis()
    print(f"✅ Server started with:")
    print(f"   - JWT Expiry: {JWT_EXPIRY_HOURS} hours")
    print(f"   - JWT Algorithm: {JWT_ALGORITHM}")
    print(f"   - Rate Limiting: {'Enabled' if RATE_LIMIT_ENABLED else 'Disabled'}")
    print(f"   - Redis: {'Connected' if redis_client else 'Disabled (no token revocation)'}")
    print(f"   - Environment: {ENVIRONMENT}")
    yield
    # Shutdown
    if redis_client:
        redis_client.close()
        print("Redis connection closed")

app.lifespan = lifespan

# ============ API ENDPOINTS ============
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>VidLink Pro API</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #0a0a0a; color: #fff; }
            h1 { color: #e50914; }
            code { background: #1a1a1a; padding: 2px 6px; border-radius: 4px; color: #e50914; }
            pre { background: #1a1a1a; padding: 15px; border-radius: 8px; overflow-x: auto; }
            .endpoint { background: #1a1a1a; margin: 10px 0; padding: 15px; border-radius: 8px; }
            .method { color: #e50914; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🎬 VidLink Pro API</h1>
        <p>JWT-based authentication for secure API access.</p>
        
        <h2>🔐 Authentication Flow:</h2>
        <div class="endpoint">
            <p><span class="method">POST</span> <code>/api/token</code> - Get JWT token</p>
            <p>Use token in requests: <code>Authorization: Bearer {token}</code></p>
        </div>
        
        <h2>📡 Endpoints:</h2>
        <div class="endpoint">
            <p><span class="method">POST</span> <code>/api/token</code> - Create new JWT token</p>
            <p><span class="method">DELETE</span> <code>/api/token</code> - Revoke current token</p>
            <p><span class="method">GET</span> <code>/movie/{id}</code> - Get movie sources</p>
            <p><span class="method">GET</span> <code>/tv/{id}/{season}/{episode}</code> - Get TV sources</p>
            <p><span class="method">GET</span> <code>/health</code> - Health check</p>
        </div>
    </body>
    </html>
    """

@app.post("/api/token")
async def create_token():
    """Create a new JWT token for the frontend"""
    try:
        token_data = create_jwt_token()
        return token_data
    except Exception as e:
        print(f"Token creation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to create token")

@app.delete("/api/token")
async def revoke_token(payload: dict = Depends(verify_jwt)):
    """Revoke the current JWT token"""
    jti = payload.get("jti")
    if jti:
        revoke_jwt_token(jti)
        return {"message": "Token revoked successfully"}
    raise HTTPException(status_code=400, detail="Invalid token")

@app.get("/movie/{movie_id}")
async def get_movie(
    movie_id: str, 
    payload: dict = Depends(verify_jwt)
):
    """Get movie stream sources - Requires valid JWT token"""
    token = encrypt_token(movie_id)
    url = f"https://vidlink.pro/api/b/movie/{token}?multiLang=1"
    
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110", timeout=30)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"VidLink returned {response.status_code}")
        
        data = response.json()
        
        if not data:
            raise HTTPException(status_code=404, detail="No source found")
        
        return data
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching movie {movie_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/tv/{tv_id}/{season}/{episode}")
async def get_tv(
    tv_id: str, 
    season: int, 
    episode: int,
    payload: dict = Depends(verify_jwt)
):
    """Get TV episode stream sources - Requires valid JWT token"""
    token = encrypt_token(tv_id)
    url = f"https://vidlink.pro/api/b/tv/{token}/{season}/{episode}?multiLang=1"
    
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110", timeout=30)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"VidLink returned {response.status_code}")
        
        data = response.json()
        
        if not data:
            raise HTTPException(status_code=404, detail="No source found")
        
        return data
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching TV {tv_id} S{season}E{episode}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint - Public"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "jwt_enabled": True,
        "jwt_algorithm": JWT_ALGORITHM,
        "redis_available": redis_client is not None,
        "environment": ENVIRONMENT
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)