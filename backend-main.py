#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🚀 COMPTAFLOW - Backend FastAPI
Production-ready avec Auth JWT + Upload + Processing + PostgreSQL + Discord Notifications
"""

# ============ IMPORTS ============
from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status, Header, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, HTMLResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from jose import jwt
import bcrypt
import os
from typing import List, Dict, Optional
import io
import uuid
from pathlib import Path
import base64
import logging
import aiohttp

# ============ IMPORTS PostgreSQL ============
from sqlalchemy.orm import Session
from database import get_db, User, Upload, UsageLog, GuestConversion, FailedConversion

# ============ IMPORTS MÉTIER ============
import pdfplumber
import pandas as pd
import re
import stripe

# ============ IMPORTS BANK DETECTOR ============
from bank_detector import validate_statement, count_transactions, get_supported_banks
import PyPDF2
from io import BytesIO

# ============ CONFIG ============
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Configurer le logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============ APP FASTAPI ============
app = FastAPI(
    title="🏦 ComptaFlow",
    description="Convertir relevés PDF en Excel",
    version="2.0.0"
)

# ============ CORS ============
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

class UploadResponse(BaseModel):
    upload_id: Optional[str] = None
    status: str
    transactions_count: int = 0
    bank_detected: Optional[str] = None
    message: str
    error: Optional[str] = None
    supported_banks: Optional[dict] = None
    can_report: Optional[bool] = None

# ============ AUTH UTILS ============
def hash_password(password: str) -> str:
    """Hash password avec bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hashed: str) -> bool:
    """Vérifier password"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Créer JWT token"""
    to_encode = data.copy()
    
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    
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

def get_current_user(authorization: Optional[str] = Header(None)):
    """Dépendance pour vérifier l'utilisateur depuis le header Authorization"""
    if not authorization:
        raise HTTPException(status_code=401, detail="No token provided")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")
        return verify_token(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid token format")

# ============ PDF UTILS ============
def extract_text_from_pdf(file_content: bytes) -> str:
    """Extrait le texte d'un fichier PDF"""
    try:
        pdf_reader = PyPDF2.PdfReader(BytesIO(file_content))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text()
        return text
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erreur lors de la lecture du PDF: {str(e)}")

# ============ BANK DETECTION & PARSING ============
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
        'JANVIER': '01', 'FÉVRIER': '02', 'FEVRIER': '02', 'MARS': '03', 'AVRIL': '04',
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
        logger.error(f"Erreur extraction: {str(e)}")
        return [], 'ERROR'

def generate_excel(transactions: List[Dict]) -> bytes:
    """Génère fichier Excel depuis transactions"""
    if not transactions:
        return None
    
    df = pd.DataFrame(transactions)
    df['Date'] = pd.to_datetime(df['Date'], format='%d/%m/%Y', errors='coerce')
    df = df.dropna(subset=['Date'])
    df['Date'] = df['Date'].dt.strftime('%d/%m/%Y')
    
    if df.empty:
        return None
    
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

# ============ DISCORD NOTIFICATIONS ============
async def send_discord_notification(failed_conversion: dict):
    """Envoie une notification Discord pour un PDF non supporté"""
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
    
    if not DISCORD_WEBHOOK_URL:
        logger.warning("⚠️ Discord webhook non configuré")
        return
    
    # Créer l'embed avec les informations du PDF
    embed = {
        "embeds": [{
            "title": "🚨 Nouveau PDF non supporté détecté",
            "description": "Un utilisateur a uploadé un PDF incompatible avec ComptaFlow",
            "color": 15158332,  # Rouge
            "fields": [
                {
                    "name": "📄 Nom du fichier",
                    "value": failed_conversion['filename'],
                    "inline": False
                },
                {
                    "name": "👤 Utilisateur",
                    "value": failed_conversion['user_email'],
                    "inline": True
                },
                {
                    "name": "🏦 Banque détectée",
                    "value": failed_conversion['bank_name'] or 'Inconnue',
                    "inline": True
                },
                {
                    "name": "❌ Message d'erreur",
                    "value": failed_conversion['error_message'][:1024],  # Limite Discord
                    "inline": False
                },
                {
                    "name": "🆔 ID du record",
                    "value": f"`{failed_conversion['id']}`",
                    "inline": True
                },
                {
                    "name": "⏰ Date",
                    "value": f"<t:{int(failed_conversion['reported_at'].timestamp())}:F>",
                    "inline": True
                }
            ],
            "footer": {
                "text": "ComptaFlow - Système de détection automatique"
            },
            "timestamp": failed_conversion['reported_at'].isoformat()
        }]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(DISCORD_WEBHOOK_URL, json=embed) as resp:
                if resp.status == 204:
                    logger.info(f"✅ Notification Discord envoyée pour {failed_conversion['filename']}")
                else:
                    error_text = await resp.text()
                    logger.error(f"❌ Erreur Discord webhook (status {resp.status}): {error_text}")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'envoi Discord : {str(e)}")

# ============ ENDPOINTS AUTH ============
@app.post("/auth/register")
async def register(user: UserRegister, db: Session = Depends(get_db)):
    """Inscription d'un nouvel utilisateur"""
    logger.info(f"📝 Registration attempt for: {user.email}")
    
    # Vérifier si l'utilisateur existe déjà
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        logger.warning(f"⚠️ User already exists: {user.email}")
        raise HTTPException(status_code=400, detail="Email déjà utilisé")
    
    try:
        # Hasher le mot de passe
        hashed_password = bcrypt.hashpw(
            user.password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
        
        # Créer l'utilisateur
        new_user = User(
            email=user.email,
            password_hash=hashed_password,
            full_name=user.full_name,  # ✅ CORRIGÉ : full_name au lieu de fullname
            subscription_tier="free"
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        logger.info(f"✅ User registered successfully: {user.email}")
        
        # Créer le token JWT
        access_token = create_access_token(data={"sub": user.email})
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "email": new_user.email,
                "full_name": new_user.full_name,  # ✅ CORRIGÉ : full_name
                "subscription_tier": new_user.subscription_tier
            }
        }
        
    except Exception as e:
        db.rollback()
        logger.error(f"❌ Registration error for {user.email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'inscription")


@app.post("/auth/login")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    """Endpoint de connexion - PostgreSQL"""
    stored_user = db.query(User).filter(User.email == user.email).first()
    if not stored_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(user.password, stored_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(data={"sub": user.email})
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "email": user.email,
            "full_name": stored_user.full_name
        }
    }

@app.get("/me")
async def get_current_user_info(
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Récupérer les informations de l'utilisateur connecté
    Utilisé par le frontend pour afficher le profil et le badge de plan
    """
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.error(f"❌ User not found in /me endpoint: {email}")
        raise HTTPException(status_code=404, detail="User not found")
    
    # Récupérer les stats d'utilisation du mois en cours
    today = datetime.now(timezone.utc)
    usage = db.query(UsageLog).filter(
        UsageLog.user_id == user.id,
        UsageLog.month == today.month,
        UsageLog.year == today.year
    ).first()
    
    # Définir les limites selon le plan
    limits = {
        "free": 5,
        "premium": 50,
        "pro": None  # Illimité
    }
    
    user_limit = limits.get(user.subscription_tier, 5)
    current_usage = usage.uploads_count if usage else 0
    
    logger.info(f"✅ User info retrieved: {email} - Plan: {user.subscription_tier}")
    
    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "subscription_tier": user.subscription_tier,
        "stripe_customer_id": user.stripe_customer_id,
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
        # Stats d'utilisation
        "usage": {
            "current_month_uploads": current_usage,
            "limit": user_limit,
            "remaining": (user_limit - current_usage) if user_limit else None,
            "percentage": round((current_usage / user_limit * 100), 1) if user_limit else 0
        }
    }


# ============ ENDPOINTS UPLOAD ELIGIBILITY ============
@app.get("/check-guest-eligibility")
async def check_guest_eligibility(request: Request, db: Session = Depends(get_db)):
    """Vérifier si l'IP peut encore faire une conversion gratuite"""
    client_ip = request.client.host
    existing = db.query(GuestConversion).filter(
        GuestConversion.ip_address == client_ip
    ).first()
    
    return {
        "eligible": existing is None,
        "ip": client_ip
    }

# ============ ENDPOINTS UPLOAD ============
@app.post("/upload-guest")
async def upload_pdf_guest(
    file: UploadFile = File(...),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Upload guest avec limitation par IP"""
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files allowed")
    
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    logger.info(f"📍 Guest conversion attempt from IP: {client_ip}")
    
    # Vérifier si cette IP a déjà converti
    existing = db.query(GuestConversion).filter(
        GuestConversion.ip_address == client_ip
    ).first()
    
    if existing:
        logger.warning(f"❌ IP {client_ip} already used free trial")
        raise HTTPException(
            status_code=403,
            detail="Vous avez déjà utilisé votre conversion gratuite. Créez un compte pour continuer !"
        )
    
    # Lire et traiter le PDF
    pdf_bytes = await file.read()
    transactions, bank_type = extract_from_pdf(pdf_bytes)
    excel_bytes = generate_excel(transactions)
    
    if not excel_bytes:
        raise HTTPException(status_code=400, detail="No transactions found")
    
    # Enregistrer la conversion
    new_conversion = GuestConversion(
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    db.add(new_conversion)
    db.commit()
    logger.info(f"✅ Guest conversion recorded for IP: {client_ip}")
    
    # Retourner le fichier Excel
    filename = file.filename.replace('.pdf', '_EXTRAIT.xlsx')
    return Response(
        content=excel_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Free-Trial-Used": "true"
        }
    )

@app.post("/upload", response_model=UploadResponse)
async def upload_pdf(
    file: UploadFile = File(...),
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Upload et traiter PDF avec VALIDATION AUTOMATIQUE + NOTIFICATION DISCORD
    - Détecte la banque
    - Vérifie la compatibilité
    - Enregistre automatiquement dans failed_conversions si incompatible
    - Envoie notification Discord
    - Convertit si compatible
    """
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files allowed")
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Lire le fichier
    pdf_bytes = await file.read()
    
    # ⭐ VALIDATION AUTOMATIQUE
    try:
        text = extract_text_from_pdf(pdf_bytes)
        validation_result = validate_statement(text)
        
        # ⭐ Si incompatible, enregistrer automatiquement et notifier
        if not validation_result['compatible']:
            logger.warning(f"⚠️ PDF non compatible uploadé par {user.email}: {file.filename}")
            
            # Encoder le PDF en base64
            pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
            
            # Insérer dans la base de données
            failed_conversion = FailedConversion(
                user_id=user.id,
                user_email=user.email,
                filename=file.filename,
                bank_name=validation_result.get('bank', 'Inconnue'),
                error_message=validation_result['message'],
                user_comment="Enregistrement automatique lors de l'upload",
                file_content=pdf_base64,
                reported_at=datetime.now(timezone.utc),
                status="pending"
            )
            
            db.add(failed_conversion)
            db.commit()
            db.refresh(failed_conversion)
            
            # ⭐ ENVOYER LA NOTIFICATION DISCORD
            await send_discord_notification({
                "id": failed_conversion.id,
                "filename": failed_conversion.filename,
                "user_email": failed_conversion.user_email,
                "bank_name": failed_conversion.bank_name,
                "error_message": failed_conversion.error_message,
                "reported_at": failed_conversion.reported_at
            })
            
            # Retourner l'erreur au frontend
            return UploadResponse(
                upload_id=None,
                status="error",
                transactions_count=0,
                bank_detected=validation_result.get('bank', 'UNKNOWN'),
                message=validation_result['message'],
                error="BANK_NOT_SUPPORTED",
                supported_banks=validation_result.get('supported_banks', {}),
                can_report=True
            )
        
        bank_type = validation_result['bank']
        
    except Exception as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Erreur de validation: {str(e)}")
    
    # ⭐ SI COMPATIBLE : Vérifier les limites
    today = datetime.utcnow()
    usage = db.query(UsageLog).filter(
        UsageLog.user_id == user.id,
        UsageLog.month == today.month,
        UsageLog.year == today.year
    ).first()
    
    if not usage:
        usage = UsageLog(
            user_id=user.id,
            month=today.month,
            year=today.year,
            uploads_count=0
        )
        db.add(usage)
        db.flush()
    
    limits = {"free": 5, "premium": 50, "pro": None}
    user_limit = limits.get(user.subscription_tier, 5)
    
    if user_limit and usage.uploads_count >= user_limit:
        raise HTTPException(
            status_code=403,
            detail=f"Limite de {user_limit} uploads atteinte ce mois-ci. Passez à Premium !"
        )
    
    # ⭐ EXTRACTION avec le bon parser
    transactions, _ = extract_from_pdf(pdf_bytes)
    excel_bytes = generate_excel(transactions)
    
    if not excel_bytes:
        raise HTTPException(status_code=400, detail="No transactions found")
    
    # Sauvegarder
    new_upload = Upload(
        user_id=user.id,
        filename=file.filename,
        bank_type=bank_type,
        transaction_count=len(transactions),
        excel_data=excel_bytes
    )
    
    db.add(new_upload)
    usage.uploads_count += 1
    db.commit()
    db.refresh(new_upload)
    
    logger.info(f"✅ Conversion successful - User: {email}, Bank: {bank_type}, Transactions: {len(transactions)}")
    
    return UploadResponse(
        upload_id=str(new_upload.id),
        status="success",
        transactions_count=len(transactions),
        bank_detected=bank_type,
        message=f"✅ {len(transactions)} transactions extraites ({usage.uploads_count}/{user_limit if user_limit else '∞'} ce mois)"
    )

@app.post("/report-failed-conversion")
async def report_failed_conversion(
    file: UploadFile = File(...),
    bank_name: str = Form(None),
    user_comment: str = Form(None),
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Permet à l'utilisateur de signaler manuellement un relevé non compatible
    avec un commentaire additionnel (complément à l'enregistrement automatique)
    """
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Lire le fichier
        content = await file.read()
        file_base64 = base64.b64encode(content).decode('utf-8')
        
        # Insérer le signalement manuel
        report = FailedConversion(
            user_id=user.id,
            user_email=user.email,
            filename=file.filename,
            bank_name=bank_name or "UNKNOWN",
            error_message="Signalement manuel par l'utilisateur",
            user_comment=user_comment,
            file_content=file_base64,
            reported_at=datetime.now(timezone.utc),
            status="pending"
        )
        
        db.add(report)
        db.commit()
        db.refresh(report)
        
        # Notification Discord
        await send_discord_notification({
            "id": report.id,
            "filename": report.filename,
            "user_email": report.user_email,
            "bank_name": report.bank_name,
            "error_message": f"Signalement manuel : {user_comment}",
            "reported_at": report.reported_at
        })
        
        logger.info(f"🚨 Failed conversion reported manually - User: {user.email}, Bank: {bank_name}, File: {file.filename}")
        
        return {
            "success": True,
            "message": "Merci pour votre signalement ! Nous allons analyser ce relevé et ajouter le support de votre banque prochainement."
        }
        
    except Exception as e:
        logger.error(f"Error reporting failed conversion: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors du signalement")

# ============ ENDPOINTS ADMIN ============
@app.get("/admin/failed-conversions")
async def get_failed_conversions(
    status: str = "pending",
    limit: int = 50,
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Liste des relevés signalés (admin only)"""
    # TODO: Ajouter vérification admin avec un champ role dans User
    user = db.query(User).filter(User.email == email).first()
    
    reports = db.query(FailedConversion)\
        .filter(FailedConversion.status == status)\
        .order_by(FailedConversion.reported_at.desc())\
        .limit(limit)\
        .all()
    
    return {
        "total": len(reports),
        "reports": [
            {
                "id": r.id,
                "user_email": r.user_email,
                "filename": r.filename,
                "bank_name": r.bank_name,
                "error_message": r.error_message,
                "user_comment": r.user_comment,
                "reported_at": r.reported_at.isoformat(),
                "status": r.status
            }
            for r in reports
        ]
    }

@app.get("/admin/download-failed-pdf/{report_id}")
async def download_failed_pdf(
    report_id: int,
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Télécharge le PDF signalé (admin only)"""
    # TODO: Ajouter vérification admin
    report = db.query(FailedConversion).filter(FailedConversion.id == report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Décoder le base64
    pdf_content = base64.b64decode(report.file_content)
    
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={report.filename}"}
    )

# ============ ENDPOINTS DOWNLOAD & HISTORY ============
@app.get("/download/{upload_id}")
async def download_excel(
    upload_id: str,
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Télécharger fichier Excel - PostgreSQL"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    upload = db.query(Upload).filter(Upload.id == upload_id).first()
    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")
    
    if upload.user_id != user.id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    filename = upload.filename.replace('.pdf', '_EXTRAIT.xlsx')
    return Response(
        content=upload.excel_data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/history")
async def get_history(
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Historique des uploads - PostgreSQL"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    uploads = db.query(Upload).filter(
        Upload.user_id == user.id
    ).order_by(Upload.created_at.desc()).all()
    
    return {
        "uploads": [
            {
                "id": str(upload.id),
                "file": upload.filename,
                "bank": upload.bank_type,
                "count": upload.transaction_count,
                "created_at": upload.created_at.isoformat()
            }
            for upload in uploads
        ]
    }

@app.get("/usage")
async def get_usage(
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Stats d'utilisation du mois en cours"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    today = datetime.utcnow()
    usage = db.query(UsageLog).filter(
        UsageLog.user_id == user.id,
        UsageLog.month == today.month,
        UsageLog.year == today.year
    ).first()
    
    limits = {"free": 5, "premium": 50, "pro": None}
    
    return {
        "uploads_count": usage.uploads_count if usage else 0,
        "limit": limits.get(user.subscription_tier, 5),
        "plan": user.subscription_tier,
        "month": today.month,
        "year": today.year
    }

# ============ STRIPE ENDPOINTS ============
@app.post("/create-checkout-session")
async def create_checkout_session(
    request: dict,
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Créer une session Stripe Checkout"""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    plan = request.get("plan")
    prices = {
        "premium": os.getenv("STRIPE_PRICE_PREMIUM"),
        "pro": os.getenv("STRIPE_PRICE_PRO")
    }
    
    if plan not in prices or not prices[plan]:
        raise HTTPException(status_code=400, detail="Invalid plan or price not configured")
    
    try:
        session = stripe.checkout.Session.create(
            customer_email=user.email,
            payment_method_types=["card"],
            line_items=[{
                "price": prices[plan],
                "quantity": 1,
            }],
            mode="subscription",
            success_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:5173')}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:5173')}/pricing",
            metadata={
                "user_id": str(user.id),
                "user_email": user.email,
                "plan": plan
            }
        )
        
        return {"url": session.url, "session_id": session.id}
        
    except Exception as e:
        logger.error(f"Stripe error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/stripe-webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """Webhook pour recevoir les événements Stripe"""
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
    
    if not webhook_secret:
        logger.warning("⚠️ STRIPE_WEBHOOK_SECRET not configured")
        return {"status": "webhook secret not configured"}
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        logger.error(f"❌ Invalid payload: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"❌ Invalid signature: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    logger.info(f"📨 Webhook received: {event['type']}")
    
    # === PAIEMENT RÉUSSI ===
    if event['type'] == "checkout.session.completed":
        session = event["data"]["object"]
        customer_id = session.get("customer")
        customer_email = session.get("customer_email")
        metadata = session.get("metadata", {})
        plan = metadata.get("plan")  # "premium" ou "pro"
    
        logger.info(f"✅ Checkout completed: {customer_email} - Plan: {plan}")
    
        if not customer_email or not plan:
            logger.error("Missing email or plan in session metadata")
            return {"status": "error", "message": "Missing metadata"}
        
        # Trouver l'utilisateur
        user = db.query(User).filter(User.email == customer_email).first()
        if not user:
            logger.error(f"❌ User not found: {customer_email}")
            raise HTTPException(status_code=401, detail="User not found")
        
        try:
            # ✅ MISE À JOUR DU PLAN ET CUSTOMER ID
            user.subscription_tier = plan
            user.stripe_customer_id = customer_id
            user.updated_at = datetime.now(timezone.utc)
            
            db.commit()
            logger.info(f"✅ User {customer_email} successfully upgraded to {plan.upper()}")
            
        except Exception as e:
            db.rollback()
            logger.error(f"❌ Error updating user {customer_email}: {str(e)}")
            return {"status": "error", "message": str(e)}
    
    # === ABONNEMENT ANNULÉ ===
    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription['customer']
        logger.info(f"❌ Subscription cancelled for customer: {customer_id}")
        
        # Récupérer l'utilisateur par customer_id
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        
        if user:
            try:
                user.subscription_tier = 'free'
                user.updated_at = datetime.now(timezone.utc)
                db.commit()
                logger.info(f"✅ User {user.email} downgraded to free")
            except Exception as e:
                db.rollback()
                logger.error(f"❌ Error downgrading user: {str(e)}")
        else:
            logger.warning(f"⚠️ User not found for customer_id: {customer_id}")
    
    # === ABONNEMENT MODIFIÉ (changement de plan) ===
    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        customer_id = subscription['customer']
        
        # Récupérer le price_id du plan actuel
        price_id = subscription['items']['data'][0]['price']['id']
        
        logger.info(f"🔄 Subscription updated for customer: {customer_id} - Price ID: {price_id}")
        
        # Mapper les price_id vers les plans
        price_to_plan = {
            os.getenv('STRIPE_PRICE_PREMIUM'): 'premium',
            os.getenv('STRIPE_PRICE_PRO'): 'pro',
        }
        
        new_plan = price_to_plan.get(price_id)
        
        if not new_plan:
            logger.warning(f"⚠️ Unknown price_id: {price_id}")
            return {"status": "error", "message": "Unknown price"}
        
        # Récupérer l'utilisateur par customer_id
        user = db.query(User).filter(User.stripe_customer_id == customer_id).first()
        
        if user:
            try:
                old_plan = user.subscription_tier
                user.subscription_tier = new_plan
                user.updated_at = datetime.now(timezone.utc)
                db.commit()
                logger.info(f"✅ User {user.email} plan changed: {old_plan} → {new_plan}")
            except Exception as e:
                db.rollback()
                logger.error(f"❌ Error updating user plan: {str(e)}")
        else:
            logger.warning(f"⚠️ User not found for customer_id: {customer_id}")


    # === PAIEMENT ÉCHOUÉ ===
    elif event['type'] == 'invoice.payment_failed':
        invoice = event['data']['object']
        customer_id = invoice['customer']
        logger.warning(f"⚠️ Payment failed for customer: {customer_id}")
        # TODO: Envoyer un email de notification à l'utilisateur
    
    # === AUTRES ÉVÉNEMENTS ===
    else:
        logger.info(f"ℹ️ Unhandled event type: {event['type']}")
    
    return {"status": "success"}

    

@app.post("/create-portal-session")
async def create_portal_session(
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Créer une session Stripe Customer Portal
    Permet à l'utilisateur de gérer son abonnement (annuler, changer de plan, etc.)
    """
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    # Vérifier que l'utilisateur a un customer_id Stripe
    if not user.stripe_customer_id:
        raise HTTPException(
            status_code=400, 
            detail="Aucun abonnement actif trouvé"
        )
    
    try:
        # Créer une session du portail client
        session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:5173')}/dashboard",
        )
        
        logger.info(f"✅ Portal session created for {email}")
        return {"url": session.url}
        
    except Exception as e:
        logger.error(f"❌ Stripe portal error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))



# ============ VALIDATION ENDPOINTS ============
@app.post("/validate-statement")
async def validate_bank_statement(
    file: UploadFile = File(...),
    email: str = Depends(get_current_user)
):
    """
    Valide si un relevé bancaire est compatible avant conversion
    - Détecte automatiquement la banque
    - Vérifie le format et la structure
    - Retourne des informations détaillées
    """
    try:
        if not file.filename.lower().endswith('.pdf'):
            raise HTTPException(
                status_code=400,
                detail="Seuls les fichiers PDF sont acceptés"
            )
        
        content = await file.read()
        text = extract_text_from_pdf(content)
        
        if not text or len(text) < 100:
            raise HTTPException(
                status_code=400,
                detail="Le PDF semble vide ou illisible. Assurez-vous qu'il contient du texte extractible."
            )
        
        validation_result = validate_statement(text)
        
        if validation_result['compatible']:
            transaction_count = count_transactions(
                text,
                validation_result['bank']
            )
            validation_result['estimated_transactions'] = transaction_count
        
        logger.info(f"Validation statement - User: {email}, "
                   f"Bank: {validation_result.get('bank', 'UNKNOWN')}, "
                   f"Compatible: {validation_result['compatible']}")
        
        return validation_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating statement: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la validation: {str(e)}"
        )

@app.get("/supported-banks")
async def get_supported_banks_endpoint():
    """Retourne la liste des banques actuellement supportées"""
    banks = get_supported_banks()
    
    return {
        "count": len(banks),
        "banks": banks,
        "details": {
            bank_code: {
                "name": description,
                "supported_formats": ["PDF"],
                "output_formats": ["Excel"]
            }
            for bank_code, description in banks.items()
        }
    }


# ============ MINI INTERFACE WEB POUR PDF FAILED ============
@app.get("/admin/pdf-downloader", response_class=HTMLResponse)
async def pdf_downloader_interface():
    """Interface web pour télécharger les PDFs échoués"""
    html_content = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ComptaFlow - Télécharger PDFs Échoués</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container {
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 800px;
                width: 100%;
                padding: 40px;
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 28px;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
            }
            .login-section, .pdfs-section {
                margin-bottom: 30px;
            }
            .hidden { display: none; }
            input, button {
                width: 100%;
                padding: 12px;
                margin: 8px 0;
                border: 2px solid #ddd;
                border-radius: 8px;
                font-size: 16px;
            }
            button {
                background: #667eea;
                color: white;
                border: none;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s;
            }
            button:hover {
                background: #5568d3;
                transform: translateY(-2px);
            }
            button:disabled {
                background: #ccc;
                cursor: not-allowed;
                transform: none;
            }
            .pdf-item {
                background: #f8f9fa;
                padding: 16px;
                margin: 12px 0;
                border-radius: 8px;
                border-left: 4px solid #667eea;
            }
            .pdf-item h3 {
                color: #333;
                margin-bottom: 8px;
                font-size: 18px;
            }
            .pdf-info {
                color: #666;
                font-size: 14px;
                margin: 4px 0;
            }
            .pdf-item button {
                margin-top: 12px;
                width: auto;
                padding: 10px 24px;
            }
            .error {
                background: #fee;
                color: #c33;
                padding: 12px;
                border-radius: 8px;
                margin: 12px 0;
            }
            .success {
                background: #efe;
                color: #3a3;
                padding: 12px;
                border-radius: 8px;
                margin: 12px 0;
            }
            .loading {
                text-align: center;
                padding: 20px;
                color: #666;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🏦 ComptaFlow Admin</h1>
            <p class="subtitle">Télécharger les PDFs des conversions échouées</p>
            
            <!-- Section Login -->
            <div class="login-section" id="loginSection">
                <input type="email" id="email" placeholder="Email" value="manidelavega@gmail.com">
                <input type="password" id="password" placeholder="Mot de passe">
                <button onclick="login()">Se connecter</button>
                <div id="loginError"></div>
            </div>
            
            <!-- Section PDFs -->
            <div class="pdfs-section hidden" id="pdfsSection">
                <button onclick="loadPDFs()" style="margin-bottom: 20px;">🔄 Recharger la liste</button>
                <div id="pdfsList"></div>
            </div>
        </div>
        
        <script>
            let token = null;
            const API_URL = window.location.origin;
            
            async function login() {
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                const errorDiv = document.getElementById('loginError');
                
                errorDiv.innerHTML = '';
                
                try {
                    const response = await fetch(`${API_URL}/auth/login`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email, password })
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        token = data.access_token;
                        
                        document.getElementById('loginSection').classList.add('hidden');
                        document.getElementById('pdfsSection').classList.remove('hidden');
                        
                        loadPDFs();
                    } else {
                        errorDiv.innerHTML = '<div class="error">❌ Email ou mot de passe incorrect</div>';
                    }
                } catch (error) {
                    errorDiv.innerHTML = '<div class="error">❌ Erreur de connexion</div>';
                }
            }
            
            async function loadPDFs() {
                const pdfsList = document.getElementById('pdfsList');
                pdfsList.innerHTML = '<div class="loading">⏳ Chargement...</div>';
                
                try {
                    const response = await fetch(`${API_URL}/admin/failed-conversions?status=pending&limit=50`, {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        
                        if (data.total === 0) {
                            pdfsList.innerHTML = '<div class="success">✨ Aucun PDF en attente !</div>';
                            return;
                        }
                        
                        pdfsList.innerHTML = data.reports.map(pdf => `
                            <div class="pdf-item">
                                <h3>📄 ${pdf.filename}</h3>
                                <div class="pdf-info">👤 Utilisateur: ${pdf.user_email}</div>
                                <div class="pdf-info">🏦 Banque: ${pdf.bank_name || 'Inconnue'}</div>
                                <div class="pdf-info">⏰ Date: ${new Date(pdf.reported_at).toLocaleString('fr-FR')}</div>
                                <div class="pdf-info">❌ Erreur: ${pdf.error_message}</div>
                                <button onclick="downloadPDF(${pdf.id}, '${pdf.filename}')">
                                    ⬇️ Télécharger
                                </button>
                            </div>
                        `).join('');
                    } else {
                        pdfsList.innerHTML = '<div class="error">❌ Erreur lors du chargement</div>';
                    }
                } catch (error) {
                    pdfsList.innerHTML = '<div class="error">❌ Erreur de connexion</div>';
                }
            }
            
            async function downloadPDF(id, filename) {
                try {
                    const response = await fetch(`${API_URL}/admin/download-failed-pdf/${id}`, {
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                    
                    if (response.ok) {
                        const blob = await response.blob();
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename;
                        document.body.appendChild(a);
                        a.click();
                        window.URL.revokeObjectURL(url);
                        document.body.removeChild(a);
                    } else {
                        alert('❌ Erreur lors du téléchargement');
                    }
                } catch (error) {
                    alert('❌ Erreur de connexion');
                }
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)



# ============ HEALTH CHECK ============
@app.get("/health")
async def health():
    """Health check"""
    return {"status": "ok", "version": "2.0.0"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "🏦 ComptaFlow",
        "version": "2.0.0",
        "status": "running",
        "features": ["auth", "upload", "validation", "discord_notifications"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
