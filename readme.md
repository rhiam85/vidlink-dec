<div align="center">
  <img src="https://socialify.git.ci/walterwhite-69/Vidlink.pro-Decryptor/image?description=1&descriptionEditable=Pure%20Python%20VidLink.pro%20Token%20Generation%20%26%20Stream%20Extractor&font=Inter&language=1&name=1&owner=1&pattern=Circuit%20Board&theme=Dark" alt="Vidlink.pro-Decryptor" width="640" height="320" />

  <p align="center">
    <a href="https://github.com/walterwhite-69/Vidlink.pro-Decryptor/stargazers"><img src="https://img.shields.io/github/stars/walterwhite-69/Vidlink.pro-Decryptor?style=for-the-badge&color=3b82f6&logo=github" alt="Stars"></a>
    <a href="https://github.com/walterwhite-69/Vidlink.pro-Decryptor/network/members"><img src="https://img.shields.io/github/forks/walterwhite-69/Vidlink.pro-Decryptor?style=for-the-badge&color=3b82f6&logo=github" alt="Forks"></a>
    <a href="https://github.com/walterwhite-69/Vidlink.pro-Decryptor/blob/main/LICENSE"><img src="https://img.shields.io/github/license/walterwhite-69/Vidlink.pro-Decryptor?style=for-the-badge&color=3b82f6" alt="License"></a>
  </p>

  <h3><b>The Ultimate VidLink.pro API Solution</b></h3>
  <p>A high-performance, pure-Python REST API that bypasses WASM encryption to retrieve direct M3U8 streaming links for Movies and TV Shows.</p>
</div>

---

### 🚀 **Features**

- ⚡ **Pure Python Implementation**: No Node.js, No Go, and No WASM overhead.
- 🔐 **Native Decryption**: Uses `PyNaCl` to replicate VidLink's `XSalsa20-Poly1305` logic.
- 🕒 **Adaptive Time-Sync**: Intelligence-based timestamp offset to prevent token expiration.
- 🕵️ **Stealth Requests**: Integrated `curl_cffi` to bypass Cloudflare WAF via TLS fingerprinting.
- 🎨 **Minimalist Documentation**: Built-in aesthetic landing page for easy testing.

---

### 🛠️ **Installation**

1. **Clone the repository**
   ```bash
   git clone https://github.com/walterwhite-69/Vidlink.pro-Decryptor.git
   cd Vidlink.pro-Decryptor
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

### 📖 **Usage**

Start the FastAPI server:
```bash
python main.py
```

Now, either visit the interactive docs at `http://localhost:8000` or call the endpoints directly:

| Endpoint | Description |
| :--- | :--- |
| `GET /movie/{tmdb_id}` | Fetch direct sources for movies. |
| `GET /tv/{tmdb_id}/{s}/{e}` | Fetch direct sources for episodes. |

---

### ⚙️ **Technical Breakdown**

This project reverse-engineered the VidLink Pro encryption logic found in their site assets. Unlike traditional solutions that rely on a browser or WASM bridge, this tool:

1. Generates a valid 24-byte nonce.
2. Constructs a binary message containing the `Media ID` and a `64-bit Big-Endian Timestamp`.
3. Encrypts the payload using a reversed production key.
4. Mimics a real Chrome 110 fingerprint to fetch the JSON response.

---

<div align="center">
  <p><b>Developer: <a href="https://github.com/walterwhite-69">Walter</a></b></p>
  <sub>Built with ❤️ for the open-source community.</sub>
</div>
