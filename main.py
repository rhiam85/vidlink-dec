import os
import time
import base64
import struct
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import nacl.secret
from curl_cffi import requests as curl_requests

app = FastAPI(title="VidLink Pro API", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

KEY_HEX = "c75136c5668bbfe65a7ecad431a745db68b5f381555b38d8f6c699449cf11fcd"
KEY = bytes.fromhex(KEY_HEX)
BOX = nacl.secret.SecretBox(KEY)
NONCE = bytes(24)

DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
    'Origin': 'https://vidlink.pro',
    'Referer': 'https://vidlink.pro/'
}

def encrypt_token(media_id: str):
    timestamp = int(time.time() + 480)
    message = media_id.encode("utf-8") + struct.pack(">Q", timestamp)
    encrypted = BOX.encrypt(message, NONCE)
    full_payload = NONCE + encrypted.ciphertext
    return base64.urlsafe_b64encode(full_payload).decode("utf-8").rstrip("=")

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>VidLink Pro API</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=Outfit:wght@300;600&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #0a0a0c;
                --card-bg: rgba(255, 255, 255, 0.03);
                --accent: #3b82f6;
                --text: #ffffff;
                --text-dim: #94a3b8;
            }
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                background: var(--bg);
                color: var(--text);
                font-family: 'Inter', sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                overflow: hidden;
            }
            .glow {
                position: absolute;
                width: 600px;
                height: 600px;
                background: radial-gradient(circle, rgba(59, 130, 246, 0.08) 0%, transparent 70%);
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                z-index: -1;
                pointer-events: none;
            }
            .container {
                max-width: 800px;
                width: 90%;
                background: var(--card-bg);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.06);
                border-radius: 24px;
                padding: 40px;
                text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            }
            h1 {
                font-family: 'Outfit', sans-serif;
                font-size: 2.5rem;
                margin-bottom: 12px;
                background: linear-gradient(to right, #fff, #94a3b8);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            p.desc {
                color: var(--text-dim);
                margin-bottom: 32px;
                font-weight: 300;
            }
            .endpoints {
                text-align: left;
                background: rgba(0, 0, 0, 0.2);
                border-radius: 16px;
                padding: 24px;
                margin-bottom: 32px;
            }
            .endpoint {
                margin-bottom: 24px;
            }
            .endpoint:last-child { margin-bottom: 0; }
            .label {
                font-family: 'Outfit', sans-serif;
                font-weight: 600;
                color: var(--accent);
                font-size: 0.8rem;
                text-transform: uppercase;
                letter-spacing: 1px;
                margin-bottom: 8px;
                display: block;
            }
            .info {
                color: var(--text-dim);
                font-size: 0.85rem;
                margin-bottom: 8px;
                font-weight: 300;
            }
            .path {
                font-family: monospace;
                background: rgba(255, 255, 255, 0.05);
                padding: 10px 14px;
                border-radius: 8px;
                display: block;
                word-break: break-all;
                color: #e2e8f0;
                margin-bottom: 12px;
                font-size: 0.9rem;
            }
            .btn {
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
            }
            .btn:hover {
                filter: brightness(1.2);
                transform: translateY(-1px);
            }
            .footer {
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
            }
            .accent-text { color: var(--accent); font-weight: 600; }
        </style>
    </head>
    <body>
        <div class="glow"></div>
        <div class="container">
            <h1>VidLink Pro Generator</h1>
            <p class="desc">Encrypted Stream Acquisition.</p>
            
            <div class="endpoints">
                <div class="endpoint">
                    <span class="label">Movie Endpoint</span>
                    <p class="info">Native source retrieval for movies using TMDb IDs.</p>
                    <span class="path">/movie/{tmdb_id}</span>
                    <a href="/movie/533535" target="_blank" class="btn">Test Movie Endpoint</a>
                </div>

                <div class="endpoint">
                    <span class="label">TV Endpoint</span>
                    <p class="info">Rapid multi-source retrieval for TV episodes.</p>
                    <span class="path">/tv/{tmdb_id}/{season}/{episode}</span>
                    <a href="/tv/105248/1/1" target="_blank" class="btn">Test TV Endpoint</a>
                </div>
            </div>
        </div>
        <div class="footer">
            Developer: <span class="accent-text">Walter</span>
        </div>
    </body>
    </html>
    """

@app.get("/movie/{movie_id}")
async def get_movie(movie_id: str):
    token = encrypt_token(movie_id)
    url = f"https://vidlink.pro/api/b/movie/{token}?multiLang=1"
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110")
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code)
        data = response.json()
        if not data:
            raise HTTPException(status_code=404, detail="No source found")
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tv/{tv_id}/{season}/{episode}")
async def get_tv(tv_id: str, season: int, episode: int):
    token = encrypt_token(tv_id)
    url = f"https://vidlink.pro/api/b/tv/{token}/{season}/{episode}?multiLang=1"
    try:
        response = curl_requests.get(url, headers=DEFAULT_HEADERS, impersonate="chrome110")
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code)
        data = response.json()
        if not data:
            raise HTTPException(status_code=404, detail="No source found")
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
