#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🚀 PENNY LANE CONVERTER - Backend FastAPI
Production-ready avec Auth JWT + Upload + Processing
"""

from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
from typing import List, Dict, Optional
import io
import uuid
from pathlib import Path

# ============ IMPORTS MÉTIER ============
import pdfplumber
import pandas as pd
import re

# ============ CONFIG ============
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI(
    title="🏦 Penny Lane Converter",
    description="Convertir relevés PDF en Excel pour Penny Lane",
    version="1.0.0"
)

# ============ CORS ============
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # À restreindre en prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ PYDANTIC MODELS ============

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class TransactionSchema(BaseModel):
    date: str
    libelle: str
    montant: float

class UploadResponse(BaseModel):
    upload_id: str
    status: str
    transactions_count: int
    bank_detected: str
    message: str

# ============ SIMULATED DATABASE ============
# En prod: remplacer par Supabase/PostgreSQL

USERS_DB = {}  # {email: {password_hash, full_name}}
UPLOADS_DB = {}  # {upload_id: {user_email, file_name, transactions, created_at}}

# ============ UTILS ============

def hash_password(password: str) -> str:
    """Hash password avec bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Vérifier password"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_access_token(email: str, expires_delta: Optional[timedelta] = None):
    """Créer JWT token"""
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.utcnow() + expires_delta
    to_encode = {"sub": email, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """Vérifier JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return email
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: str = None):
    """Dépendance pour vérifier l'utilisateur"""
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    return verify_token(token)

# ============ EXTRACTION (MOTEUR PRINCIPAL) ============

def detect_bank_format(text: str) -> str:
    """Détecte le format bancaire"""
    text_upper = text.upper()
    if 'CREDIT AGRICOLE' in text_upper:
        return 'CA'
    elif 'BANQUE POPULAIRE' in text_upper:
        return 'BP'
    elif 'CREDIT LYONNAIS' in text_upper or 'LCL' in text_upper:
        return 'LCL'
    elif 'SOCIETE GENERALE' in text_upper or 'SOCIÉTÉ GÉNÉRALE' in text_upper:
        return 'SG'
    elif 'BNP' in text_upper:
        return 'BNP'
    else:
        return 'UNKNOWN'

def extract_ca_transactions(lines: List[str]) -> List[Dict]:
    """Format CA: JJ.MM COMMERCE LIEU MONTANT"""
    transactions = []
    skip_keywords = ['TOTAL', 'Date', 'Montant', 'Commerce', 'Page']
    
    for line in lines:
        if any(skip in line for skip in skip_keywords):
            continue
        
        date_match = re.search(r'^(\d{1,2}\.\d{2})\s+', line)
        montant_match = re.search(r'(-?\d{1,5},\d{2})$', line)
        
        if date_match and montant_match:
            try:
                date_str = date_match.group(1)
                montant_str = montant_match.group(1)
                
                start_idx = date_match.end()
                end_idx = montant_match.start()
                middle_text = line[start_idx:end_idx].strip()
                
                if not middle_text:
                    continue
                
                jour, mois = date_str.split('.')
                date_format = f"{jour}/{mois}/2025"
                montant = float(montant_str.replace(',', '.'))
                
                transactions.append({
                    'Date': date_format,
                    'Libellé': middle_text,
                    'Montant': -montant
                })
            except:
                pass
    
    return transactions

def extract_bp_transactions(lines: List[str]) -> List[Dict]:
    """Format BP: JJ/MM/YY COMMERCE ADRESSE MONTANT €"""
    transactions = []
    skip_keywords = ['DATE', 'NOM', 'MONTANT', 'Page', 'TOTAL']
    
    for line in lines:
        if any(skip in line for skip in skip_keywords):
            continue
        
        date_match = re.match(r'^(\d{1,2})/(\d{1,2})/(\d{2})\s+', line.strip())
        montant_match = re.search(r'(\d+[.,]\d{2})\s*€\s*$', line.strip())
        
        if date_match and montant_match:
            try:
                jour = date_match.group(1)
                mois = date_match.group(2)
                annee = f"20{date_match.group(3)}"
                date_format = f"{jour}/{mois}/{annee}"
                
                montant = float(montant_match.group(1).replace(',', '.'))
                
                start_idx = date_match.end()
                end_idx = montant_match.start()
                middle_text = line.strip()[start_idx:end_idx].strip()
                
                transactions.append({
                    'Date': date_format,
                    'Libellé': middle_text,
                    'Montant': -montant
                })
            except:
                pass
    
    return transactions

def extract_lcl_transactions(lines: List[str]) -> List[Dict]:
    """Format LCL: PAIEMENTS PAR CARTE"""
    transactions = []
    
    mois_dict = {
        'JANVIER': '01', 'FÉVRIER': '02', 'MARS': '03', 'AVRIL': '04',
        'MAI': '05', 'JUIN': '06', 'JUILLET': '07', 'AOÛT': '08', 'AOUT': '08',
        'SEPTEMBRE': '09', 'OCTOBRE': '10', 'NOVEMBRE': '11', 'DÉCEMBRE': '12', 'DECEMBRE': '12'
    }
    
    annee = None
    mois_num = None
    
    for line in lines:
        match = re.search(r'PAIEMENTS PAR CARTE DE\s+(\w+)\s*(\d{4})', line)
        if match:
            mois_txt = match.group(1).upper()
            annee = match.group(2)
            mois_num = mois_dict.get(mois_txt, None)
            break
    
    if not annee:
        annee = '2025'
    
    in_card_section = False
    skip_keywords = ['PAIEMENTS', 'TOTAL', 'MONTANT', 'CARTE', 'RELEVE']
    
    for line in lines:
        if 'PAIEMENTS PAR CARTE DE' in line:
            in_card_section = True
            continue
        
        if in_card_section and 'RELEVE DE COMPTE' in line:
            in_card_section = False
            continue
        
        if not in_card_section or not line.strip():
            continue
        
        if any(skip in line for skip in skip_keywords):
            continue
        
        montant_match = re.search(r'(\d+[.,]\d{2})\s*$', line.strip())
        
        if montant_match:
            try:
                montant = float(montant_match.group(1).replace(',', '.'))
                libelle = line.strip()[:montant_match.start()].strip()
                
                if not libelle or len(libelle) < 3:
                    continue
                
                date_match = re.search(r'LE\s+(\d{1,2})/(\d{1,2})', libelle)
                
                if date_match:
                    jour = date_match.group(1)
                    mois = date_match.group(2)
                    date_format = f"{jour}/{mois}/{annee}"
                elif mois_num:
                    date_format = f"01/{mois_num}/{annee}"
                else:
                    continue
                
                transactions.append({
                    'Date': date_format,
                    'Libellé': libelle,
                    'Montant': -montant
                })
            except:
                pass
    
    return transactions

def extract_from_pdf(pdf_bytes: bytes) -> tuple:
    """Extrait transactions depuis PDF"""
    try:
        pdf_file = io.BytesIO(pdf_bytes)
        
        with pdfplumber.open(pdf_file) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text() + "\n"
            
            bank_type = detect_bank_format(text)
            lines = [l.strip() for l in text.split('\n') if l.strip()]
            
            if bank_type == 'CA':
                transactions = extract_ca_transactions(lines)
            elif bank_type == 'BP':
                transactions = extract_bp_transactions(lines)
            elif bank_type == 'LCL':
                transactions = extract_lcl_transactions(lines)
            else:
                transactions = []
            
            return transactions, bank_type
    
    except Exception as e:
        print(f"Erreur extraction: {str(e)}")
        return [], 'ERROR'

def generate_excel(transactions: List[Dict]) -> bytes:
    """Génère fichier Excel depuis transactions"""
    if not transactions:
        return None
    
    df = pd.DataFrame(transactions)
    
    # Validation dates
    df['Date'] = pd.to_datetime(df['Date'], format='%d/%m/%Y', errors='coerce')
    df = df.dropna(subset=['Date'])
    df['Date'] = df['Date'].dt.strftime('%d/%m/%Y')
    
    if df.empty:
        return None
    
    # Générer Excel en mémoire
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df[['Date', 'Libellé', 'Montant']].to_excel(
            writer, index=False, sheet_name='Relevé'
        )
        
        ws = writer.sheets['Relevé']
        ws.column_dimensions['A'].width = 12
        ws.column_dimensions['B'].width = 50
        ws.column_dimensions['C'].width = 15
    
    output.seek(0)
    return output.getvalue()

# ============ ENDPOINTS AUTH ============

@app.post("/api/auth/register", response_model=Token)
async def register(user: UserRegister):
    """Enregistrer nouvel utilisateur"""
    if user.email in USERS_DB:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    USERS_DB[user.email] = {
        "password_hash": hash_password(user.password),
        "full_name": user.full_name,
        "created_at": datetime.utcnow()
    }
    
    token = create_access_token(user.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@app.post("/api/auth/login", response_model=Token)
async def login(user: UserLogin):
    """Connexion utilisateur"""
    if user.email not in USERS_DB:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    stored_user = USERS_DB[user.email]
    if not verify_password(user.password, stored_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(user.email)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

# ============ ENDPOINTS UPLOAD ============

@app.post("/api/upload", response_model=UploadResponse)
async def upload_pdf(file: UploadFile = File(...), token: str = None):
    """Upload et traiter PDF"""
    email = get_current_user(token)
    
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files allowed")
    
    # Lire le PDF
    pdf_bytes = await file.read()
    
    # Extraire
    transactions, bank_type = extract_from_pdf(pdf_bytes)
    
    # Générer Excel
    excel_bytes = generate_excel(transactions)
    
    if not excel_bytes:
        raise HTTPException(status_code=400, detail="No transactions found")
    
    # Sauvegarder
    upload_id = str(uuid.uuid4())
    UPLOADS_DB[upload_id] = {
        "user_email": email,
        "file_name": file.filename,
        "bank": bank_type,
        "transactions": transactions,
        "excel_bytes": excel_bytes,
        "created_at": datetime.utcnow()
    }
    
    return UploadResponse(
        upload_id=upload_id,
        status="success",
        transactions_count=len(transactions),
        bank_detected=bank_type,
        message=f"✅ {len(transactions)} transactions extraites de {bank_type}"
    )

@app.get("/api/download/{upload_id}")
async def download_excel(upload_id: str, token: str = None):
    """Télécharger fichier Excel"""
    email = get_current_user(token)
    
    if upload_id not in UPLOADS_DB:
        raise HTTPException(status_code=404, detail="Upload not found")
    
    upload = UPLOADS_DB[upload_id]
    if upload["user_email"] != email:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    return {
        "file": upload["excel_bytes"].hex(),
        "filename": upload["file_name"].replace('.pdf', '_EXTRAIT.xlsx')
    }

@app.get("/api/history")
async def get_history(token: str = None):
    """Historique des uploads"""
    email = get_current_user(token)
    
    user_uploads = [
        {
            "id": uid,
            "file": data["file_name"],
            "bank": data["bank"],
            "count": len(data["transactions"]),
            "created_at": data["created_at"].isoformat()
        }
        for uid, data in UPLOADS_DB.items()
        if data["user_email"] == email
    ]
    
    return {"uploads": user_uploads}

# ============ HEALTH CHECK ============

@app.get("/api/health")
async def health():
    """Health check"""
    return {"status": "ok", "version": "1.0.0"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "🏦 Penny Lane Converter",
        "version": "1.0.0",
        "status": "running"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
