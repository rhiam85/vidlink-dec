import os
import time
import base64
import struct
import json
import re
import secrets
from datetime import datetime, timedelta
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
# Security settings - API KEY AUTH ENABLED
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "true").lower() == "true"
API_KEYS = os.getenv("API_KEYS", "").split(",") if os.getenv("API_KEYS") else []

# Generate a default API key if none provided (for development)
if ENABLE_AUTH and not API_KEYS:
    default_key = secrets.token_urlsafe(32)
    API_KEYS = [default_key]
    print(f"⚠️ No API keys found in environment. Using generated key: {default_key}")
    print(f"⚠️ Please add this to your .env file: API_KEYS={default_key}")

# Rate limiting
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "1000"))

# Redis configuration (Aiven - uses Let's Encrypt, no CA cert needed)
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
REDIS_SSL = os.getenv("REDIS_SSL", "true").lower() == "true"

ENVIRONMENT = os.getenv("ENVIRONMENT", "production")  # development or production

# Allowed domains - ALWAYS include localhost for testing (remove in production if needed)
ALLOWED_DOMAINS = [
    r"^https?://([a-zA-Z0-9-]+\.)*cinehub\.top$",
    r"^https?://([a-zA-Z0-9-]+\.)*vidfy\.sbs$",
    # Always allow localhost for development/testing even in production
    r"^https?://localhost(:\d+)?$",
    r"^https?://127\.0\.0\.1(:\d+)?$",
]

# Add additional development domains if in development mode
if ENVIRONMENT == "development":
    ALLOWED_DOMAINS.extend([
        r"^https?://0\.0\.0\.0(:\d+)?$",
    ])
    print("⚠️ Running in DEVELOPMENT mode - additional localhost allowed")

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

# Security scheme for API key authentication
security = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ============ REDIS CONNECTION ============
redis_client = None

def init_redis():
    """Initialize Redis connection with fallback to memory cache"""
    global redis_client
    try:
        # Simple connection parameters - no CA cert needed for Aiven (Let's Encrypt)
        connection_params = {
            'host': REDIS_HOST,
            'port': REDIS_PORT,
            'password': REDIS_PASSWORD,
            'decode_responses': True,
            'socket_connect_timeout': 5,
            'socket_keepalive': True,
            'retry_on_timeout': True,
        }
        
        # Enable SSL if configured (Aiven requires SSL)
        if REDIS_SSL:
            connection_params['ssl'] = True
            # No ssl_ca_certs needed - Let's Encrypt is globally trusted
        
        redis_client = redis.Redis(**connection_params)
        redis_client.ping()
        print("✅ Connected to Aiven Redis successfully")
        return True
    except Exception as e:
        print(f"⚠️ Redis connection failed: {e}")
        print("⚠️ Falling back to in-memory cache")
        redis_client = None
        return False

# ============ FASTAPI APP ============
app = FastAPI(
    title="VidLink Pro API", 
    docs_url=None, 
    redoc_url=None,
)

# ============ MIDDLEWARES ============
@app.middleware("http")
async def restrict_domains(request: Request, call_next):
    """Restrict access to allowed domains only"""
    # Skip for root endpoint (HTML documentation)
    if request.url.path == "/":
        return await call_next(request)
    
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    
    # For testing: Allow if no origin/referer (direct API calls)
    if not origin and not referer:
        # Still check if it's a direct API call (like from curl)
        # You can log this for monitoring
        print(f"⚠️ Direct API call from IP: {request.client.host}")
        return await call_next(request)
    
    # Check if request is from allowed domain
    is_allowed = False
    for header in [origin, referer]:
        if header:
            for pattern in ALLOWED_PATTERNS:
                if pattern.match(header):
                    is_allowed = True
                    break
        if is_allowed:
            break
    
    if not is_allowed:
        print(f"❌ Blocked request from origin={origin}, referer={referer}")
        return JSONResponse(
            status_code=403,
            content={
                "error": "Access Denied",
                "message": f"This API can only be accessed from allowed domains. Got: {origin or referer}"
            }
        )
    
    return await call_next(request)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware using Redis"""
    if not RATE_LIMIT_ENABLED:
        return await call_next(request)
    
    # Skip rate limiting for root endpoint
    if request.url.path == "/":
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
                return JSONResponse(status_code=429, content={"error": "Rate limit exceeded. Try again later."})
            
            # Check hour limit
            hour_count = redis_client.get(hour_key)
            if hour_count and int(hour_count) >= RATE_LIMIT_PER_HOUR:
                return JSONResponse(status_code=429, content={"error": "Hourly rate limit exceeded."})
            
            # Increment counters
            redis_client.incr(minute_key)
            redis_client.expire(minute_key, 60)
            redis_client.incr(hour_key)
            redis_client.expire(hour_key, 3600)
            
        except Exception as e:
            print(f"Rate limit error: {e}")
            # Continue if Redis fails
    
    return await call_next(request)

# ============ AUTHENTICATION ============
async def verify_api_key(
    bearer_auth: HTTPAuthorizationCredentials = Depends(security),
    api_key_header_value: str = Depends(api_key_header)
):
    """Verify API key from either Bearer token or X-API-Key header"""
    if not ENABLE_AUTH:
        return None
    
    api_key = None
    
    # Check Bearer token first
    if bearer_auth:
        api_key = bearer_auth.credentials
    
    # Then check X-API-Key header
    if not api_key and api_key_header_value:
        api_key = api_key_header_value
    
    # Also check query parameter for API key (for easier testing)
    if not api_key:
        from fastapi import Request
        # This will be handled by the request object in the endpoint
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Provide via 'Authorization: Bearer <key>', 'X-API-Key: <key>', or query parameter '?api_key=<key>'",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if api_key not in API_KEYS:
        # Log failed attempt (for monitoring)
        print(f"⚠️ Failed API key attempt: {api_key[:10]}...")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return api_key

# ============ CACHE FUNCTIONS ============
def get_cached(key: str):
    """Get value from cache (Redis or memory)"""
    if redis_client:
        try:
            value = redis_client.get(key)
            if value:
                return json.loads(value)
        except:
            return None
    return None

def set_cached(key: str, value, ttl: int = 300):
    """Set value in cache with TTL (default 5 minutes)"""
    if redis_client:
        try:
            redis_client.setex(key, ttl, json.dumps(value))
        except:
            pass

# ============ LIFESPAN ============
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_redis()
    print(f"✅ Server started with:")
    print(f"   - Authentication: {'ENABLED' if ENABLE_AUTH else 'Disabled'}")
    if ENABLE_AUTH:
        print(f"   - Active API Keys: {len(API_KEYS)} key(s)")
    print(f"   - Rate Limiting: {'Enabled' if RATE_LIMIT_ENABLED else 'Disabled'}")
    print(f"   - Redis: {'Connected' if redis_client else 'Fallback to memory'}")
    print(f"   - Allowed Domains: {[p.pattern for p in ALLOWED_PATTERNS]}")
    yield
    # Shutdown
    if redis_client:
        redis_client.close()
        print("Redis connection closed")

app.lifespan = lifespan

# ============ CORS CONFIGURATION ============
# Build CORS origins - ALWAYS include localhost for testing
cors_origins = [
    # Production domains
    "https://cinehub.top",
    "https://*.cinehub.top",
    "https://vidfy.sbs",
    "https://*.vidfy.sbs",
    # Always allow localhost for development/testing even in production
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8000",
]

# Add additional development origins if in development mode
if ENVIRONMENT == "development":
    cors_origins.extend([
        "http://0.0.0.0:3000",
        "http://0.0.0.0:5173",
        "http://0.0.0.0:8000",
    ])
    print("⚠️ CORS: Development origins enabled")

print(f"✅ CORS Allowed Origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "OPTIONS"],  # Added OPTIONS for preflight requests
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# ============ HELPER FUNCTIONS ============
def encrypt_token(media_id: str):
    """Encrypt media ID with timestamp"""
    timestamp = int(time.time() + 480)
    message = media_id.encode("utf-8") + struct.pack(">Q", timestamp)
    encrypted = BOX.encrypt(message, NONCE)
    full_payload = NONCE + encrypted.ciphertext
    return base64.urlsafe_b64encode(full_payload).decode("utf-8").rstrip("=")

def validate_media_id(media_id: str):
    """Validate input to prevent injection"""
    if not media_id or len(media_id) > 20:
        raise HTTPException(status_code=400, detail="Invalid media ID format")
    if not media_id.replace("-", "").isdigit():
        raise HTTPException(status_code=400, detail="Media ID must be numeric")
    return True

# ============ API ENDPOINTS ============
@app.get("/", response_class=HTMLResponse)
async def home():
    """HTML documentation page"""
    auth_status = "🔒 API Key Authentication Required" if ENABLE_AUTH else "🔓 Open Access"
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VidLink Pro API</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=Outfit:wght@300;600&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg: #0a0a0c;
                --card-bg: rgba(255, 255, 255, 0.03);
                --accent: #3b82f6;
                --text: #ffffff;
                --text-dim: #94a3b8;
                --success: #10b981;
                --warning: #f59e0b;
            }}
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                background: var(--bg);
                color: var(--text);
                font-family: 'Inter', sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                overflow: hidden;
            }}
            .glow {{
                position: absolute;
                width: 600px;
                height: 600px;
                background: radial-gradient(circle, rgba(59, 130, 246, 0.08) 0%, transparent 70%);
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                z-index: -1;
                pointer-events: none;
            }}
            .container {{
                max-width: 800px;
                width: 90%;
                background: var(--card-bg);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.06);
                border-radius: 24px;
                padding: 40px;
                text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            }}
            h1 {{
                font-family: 'Outfit', sans-serif;
                font-size: 2.5rem;
                margin-bottom: 12px;
                background: linear-gradient(to right, #fff, #94a3b8);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            .auth-badge {{
                display: inline-block;
                background: {'#10b981' if ENABLE_AUTH else '#f59e0b'};
                color: #000;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.75rem;
                font-weight: 600;
                margin-bottom: 16px;
            }}
            p.desc {{
                color: var(--text-dim);
                margin-bottom: 32px;
                font-weight: 300;
            }}
            .endpoints {{
                text-align: left;
                background: rgba(0, 0, 0, 0.2);
                border-radius: 16px;
                padding: 24px;
                margin-bottom: 32px;
            }}
            .endpoint {{
                margin-bottom: 24px;
            }}
            .endpoint:last-child {{ margin-bottom: 0; }}
            .label {{
                font-family: 'Outfit', sans-serif;
                font-weight: 600;
                color: var(--accent);
                font-size: 0.8rem;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 8px;
                display: block;
            }}
            .info {{
                color: var(--text-dim);
                font-size: 0.85rem;
                margin-bottom: 8px;
                font-weight: 300;
            }}
            .path {{
                font-family: monospace;
                background: rgba(255, 255, 255, 0.05);
                padding: 10px 14px;
                border-radius: 8px;
                display: block;
                word-break: break-all;
                color: #e2e8f0;
                margin-bottom: 12px;
                font-size: 0.9rem;
            }}
            .btn {{
                display: inline-block;
                padding: 10px 20px;
                background: var(--accent);
                color: #000;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                font-size: 0.9rem;
                transition: all 0.2s;
                font-family: 'Outfit', sans-serif;
            }}
            .btn:hover {{
                filter: brightness(1.2);
                transform: translateY(-1px);
            }}
            .footer {{
                position: absolute;
                bottom: 40px;
                left: 50%;
                transform: translateX(-50%);
                font-family: 'Outfit', sans-serif;
                font-weight: 300;
                letter-spacing: 2px;
                color: var(--text-dim);
                opacity: 0.6;
                font-size: 0.8rem;
            }}
            .accent-text {{ color: var(--accent); font-weight: 600; }}
            .code-block {{
                background: rgba(0, 0, 0, 0.4);
                border-radius: 8px;
                padding: 12px;
                margin-top: 8px;
                font-family: monospace;
                font-size: 0.8rem;
                color: #94a3b8;
            }}
        </style>
    </head>
    <body>
        <div class="glow"></div>
        <div class="container">
            <div class="auth-badge">{auth_status}</div>
            <h1>VidLink Pro Generator</h1>
            <p class="desc">Encrypted Stream Acquisition.</p>
            
            <div class="endpoints">
                <div class="endpoint">
                    <span class="label">Movie Endpoint</span>
                    <p class="info">Native source retrieval for movies using TMDb IDs.</p>
                    <span class="path">/movie/{{tmdb_id}}</span>
                    <a href="/movie/533535" target="_blank" class="btn">Test Movie Endpoint</a>
                </div>

                <div class="endpoint">
                    <span class="label">TV Endpoint</span>
                    <p class="info">Rapid multi-source retrieval for TV episodes.</p>
                    <span class="path">/tv/{{tmdb_id}}/{{season}}/{{episode}}</span>
                    <a href="/tv/105248/1/1" target="_blank" class="btn">Test TV Endpoint</a>
                </div>
            </div>
            
            {'<div class="code-block" style="margin-top: 20px;">🔑 API Key Required for all endpoints<br>Use header: <strong>X-API-Key: YOUR_KEY</strong> or <strong>Authorization: Bearer YOUR_KEY</strong></div>' if ENABLE_AUTH else ''}
        </div>
        <div class="footer">
            Developer: <span class="accent-text">Walter</span>
        </div>
    </body>
    </html>
    """

@app.get("/movie/{movie_id}")
async def get_movie(
    movie_id: str, 
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    """Get movie stream sources - API Key Required"""
    # Validate input
    validate_media_id(movie_id)
    
    # Check cache
    cache_key = f"movie:{movie_id}"
    cached_data = get_cached(cache_key)
    if cached_data:
        return cached_data
    
    # Fetch from VidLink
    token = encrypt_token(movie_id)
    url = f"https://vidlink.pro/api/b/movie/{token}?multiLang=1"
    
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110", timeout=30)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"VidLink API returned {response.status_code}")
        
        data = response.json()
        if not data or (isinstance(data, dict) and not data.get("sources")):
            raise HTTPException(status_code=404, detail="No source found")
        
        # Cache for 5 minutes
        set_cached(cache_key, data, ttl=300)
        
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
    request: Request,
    api_key: str = Depends(verify_api_key)
):
    """Get TV episode stream sources - API Key Required"""
    # Validate input
    validate_media_id(tv_id)
    
    if season < 1 or episode < 1:
        raise HTTPException(status_code=400, detail="Season and episode must be positive numbers")
    
    # Check cache
    cache_key = f"tv:{tv_id}:{season}:{episode}"
    cached_data = get_cached(cache_key)
    if cached_data:
        return cached_data
    
    # Fetch from VidLink
    token = encrypt_token(tv_id)
    url = f"https://vidlink.pro/api/b/tv/{token}/{season}/{episode}?multiLang=1"
    
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110", timeout=30)
        
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=f"VidLink API returned {response.status_code}")
        
        data = response.json()
        if not data or (isinstance(data, dict) and not data.get("sources")):
            raise HTTPException(status_code=404, detail="No source found")
        
        # Cache for 5 minutes
        set_cached(cache_key, data, ttl=300)
        
        return data
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error fetching TV {tv_id} S{season}E{episode}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/health")
async def health_check():
    """Health check endpoint - Public (no auth required)"""
    status = {
        "status": "healthy",
        "timestamp": time.time(),
        "redis": redis_client is not None,
        "auth_enabled": ENABLE_AUTH,
        "environment": ENVIRONMENT,
        "active_keys": len(API_KEYS) if ENABLE_AUTH else 0
    }
    return status
@app.get("/debug-vidlink/{movie_id}")
async def debug_vidlink(movie_id: str, api_key: str = Depends(verify_api_key)):
    """Debug VidLink API connection"""
    from curl_cffi import requests as curl_requests
    
    token = encrypt_token(movie_id)
    url = f"https://vidlink.pro/api/b/movie/{token}?multiLang=1"
    
    results = {
        "movie_id": movie_id,
        "token": token,
        "url": url,
        "attempts": []
    }
    
    # Try with different impersonations
    impersonations = ["chrome110", "chrome120", "safari15_5", "edge101"]
    
    for impersonate in impersonations:
        try:
            print(f"Trying with impersonate: {impersonate}")
            response = curl_requests.get(
                url, 
                headers=DEFAULT_HEADERS, 
                impersonate=impersonate, 
                timeout=30
            )
            
            results["attempts"].append({
                "impersonate": impersonate,
                "status": response.status_code,
                "has_sources": bool(response.json().get('sources')) if response.status_code == 200 else False
            })
            
            if response.status_code == 200:
                data = response.json()
                if data.get('sources'):
                    results["success"] = True
                    results["sources_count"] = len(data['sources'])
                    return results
        except Exception as e:
            results["attempts"].append({
                "impersonate": impersonate,
                "error": str(e)
            })
    
    return results

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)