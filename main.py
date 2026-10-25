import os
import hashlib
import sqlite3
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import httpx
from google import genai
from supabase import create_client, Client

load_dotenv()

app = FastAPI(title="Xavfsiz Maskan API")

# CORS sozlamalari (Frontend ulana olishi uchun)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API kalitlar va mijozlarni sozlash
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

gemini_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL and SUPABASE_KEY else None

# SQLite Kesh bazasini ishga tushirish (AI va VT limitlarini tejash uchun)
def init_cache_db():
    conn = sqlite3.connect("cache.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_cache (
            file_hash TEXT PRIMARY KEY,
            result TEXT,
            source TEXT
        )
    """)
    conn.commit()
    conn.close()

init_cache_db()

def get_from_cache(file_hash: str):
    conn = sqlite3.connect("cache.db")
    cursor = conn.cursor()
    cursor.execute("SELECT result, source FROM scan_cache WHERE file_hash = ?", (file_hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"result": row[0], "source": row[1], "cached": True}
    return None

def save_to_cache(file_hash: str, result: str, source: str):
    conn = sqlite3.connect("cache.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO scan_cache (file_hash, result, source) VALUES (?, ?, ?)", 
                   (file_hash, result, source))
    conn.commit()
    conn.close()

def log_to_supabase(action_type: str, details: str, status: str):
    if supabase:
        try:
            supabase.table("logs").insert({
                "action_type": action_type,
                "details": details,
                "status": status
            }).execute()
        except Exception as e:
            print(f"Supabase log xatosi: {e}")

@app.get("/")
def home():
    return {"status": "ok", "message": "Xavfsiz Maskan Backend Serveri Ishlamoqda"}

# 1. VirusTotal API orqali Fayl Hash-skaneri
@app.post("/scan-hash")
async def scan_file_hash(file: UploadFile = File(...)):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    # Keshda bor-yo'qligini tekshirish
    cached = get_from_cache(file_hash)
    if cached:
        return cached

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_count = stats.get("malicious", 0)
        
        result_str = f"Xavfli (Antiviruslar aniqladi: {malicious_count})" if malicious_count > 0 else "Xavfsiz"
        status = "BLOCKED" if malicious_count > 0 else "ALLOWED"
        
        save_to_cache(file_hash, result_str, "VirusTotal")
        log_to_supabase("FILE_HASH_SCAN", f"{file.filename} ({file_hash[:8]})", status)
        
        return {"file_hash": file_hash, "result": result_str, "details": stats, "cached": False}
    else:
        result_str = "Noma'lum fayl (VirusTotal bazasida topilmadi)"
        log_to_supabase("FILE_HASH_SCAN", f"{file.filename}", "UNKNOWN")
        return {"file_hash": file_hash, "result": result_str, "cached": False}

# 2. Gemini Vision API orqali Rasm Kontent Skaneri
@app.post("/scan-image")
async def scan_image_content(file: UploadFile = File(...)):
    content = await file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    cached = get_from_cache(file_hash)
    if cached:
        return cached

    if not gemini_client:
        raise HTTPException(status_code=500, detail="Gemini API Sozlanmagan")

    prompt = (
        "Ushbu rasmni kiberxavfsizlik va ta'lim muassasasi xavfsizligi nuqtai nazaridan tahlil qil. "
        "Rasmda quyidagilar bormi: 18+ mazmun, zo'ravonlik, kiber-hujum / fishing parollari, qurol yoki taqiqlangan moddalar? "
        "Javobni juda qisqa va aniq ber: 'XAVFSIZ' yoki 'TAQIQLANGAN: [sababi]'."
    )

    try:
        response = gemini_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[
                {"mime_type": file.content_type or "image/jpeg", "data": content},
                prompt
            ]
        )
        res_text = response.text.strip()
        status = "BLOCKED" if "TAQIQLANGAN" in res_text.upper() else "ALLOWED"
        
        save_to_cache(file_hash, res_text, "GeminiVision")
        log_to_supabase("IMAGE_AI_SCAN", file.filename, status)
        
        return {"filename": file.filename, "result": res_text, "cached": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gemini AI Tahlil Xatosi: {str(e)}")