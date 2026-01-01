#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COMPTAFLOW - Backend FastAPI
Production-ready avec Auth, JWT, Upload Processing, PostgreSQL, Discord Notifications
"""

# ============================================================================
# IMPORTS
# ============================================================================

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

# PostgreSQL
from sqlalchemy.orm import Session
from database import get_db, User, Upload, UsageLog, GuestConversion, FailedConversion

# Stripe
import stripe

# Bank detection
from bank_detector import validate_statement, count_transactions, get_supported_banks

# Parsers (nouveau module séparé)
from parsers import (
    extract_text_from_pdf,
    extract_from_pdf,
    generate_excel
)

import sys
# Forcer l'affichage immédiat des logs (sans buffer)
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# ============================================================================
# CONFIG
# ============================================================================

SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# ============================================================================
# CONFIGURATION DU LOGGING (APRÈS LES IMPORTS)
# ============================================================================

import sys
import logging

# Forcer l'affichage immédiat
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# Configurer le logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ],
    force=True  # Forcer la reconfiguration
)

# Logger principal
logger = logging.getLogger(__name__)

# Activer les logs des modules spécifiques
logging.getLogger('parsers').setLevel(logging.INFO)
logging.getLogger('uvicorn').setLevel(logging.WARNING)  # Réduire le bruit de uvicorn
logging.getLogger('bank_detector').setLevel(logging.INFO)



# ============================================================================
# APP FASTAPI
# ============================================================================

app = FastAPI(
    title="ComptaFlow",
    description="Convertir relevés PDF en Excel",
    version="2.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

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
    error_type: Optional[str] = None
    supported_banks: Optional[dict] = None
    can_report: Optional[bool] = None

# ============================================================================
# AUTH UTILS
# ============================================================================

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

# ============================================================================
# DISCORD NOTIFICATIONS
# ============================================================================

async def send_discord_notification(failed_conversion: dict):
    """Envoie une notification Discord pour un PDF non supporté"""
    DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')

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
                    "value": failed_conversion['bank_name'] or "Inconnue",
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
                    "name": "📅 Date",
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
        logger.error(f"❌ Erreur lors de l'envoi Discord: {str(e)}")

# ============================================================================
# ENDPOINTS - AUTH
# ============================================================================

@app.post("/auth/register")
async def register(user: UserRegister, db: Session = Depends(get_db)):
    """Inscription d'un nouvel utilisateur"""
    logger.info(f"📝 Registration attempt for {user.email}")

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
            full_name=user.full_name,
            subscription_tier='free'
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
                "full_name": new_user.full_name,
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
    """Récupérer les informations de l'utilisateur connecté"""
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
        'free': 5,
        'premium': 50,
        'pro': None  # Illimité
    }

    user_limit = limits.get(user.subscription_tier, 5)
    current_usage = usage.uploads_count if usage else 0

    logger.info(f"ℹ️ User info retrieved: {email} - Plan: {user.subscription_tier}")

    return {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "subscription_tier": user.subscription_tier,
        "stripe_customer_id": user.stripe_customer_id,
        "created_at": user.created_at.isoformat(),
        "updated_at": user.updated_at.isoformat(),
        "usage": {
            "current_month_uploads": current_usage,
            "limit": user_limit,
            "remaining": user_limit - current_usage if user_limit else None,
            "percentage": round((current_usage / user_limit * 100), 1) if user_limit else 0
        }
    }

# ============================================================================
# ENDPOINTS - UPLOAD & ELIGIBILITY
# ============================================================================

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

@app.post("/upload-guest")
async def upload_pdf_guest(
    file: UploadFile = File(...),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Upload guest avec limitation par IP"""
    if file.content_type != 'application/pdf':
        raise HTTPException(status_code=400, detail="Only PDF files allowed")

    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', '')

    logger.info(f"🔓 Guest conversion attempt from IP: {client_ip}")

    # Vérifier si cette IP a déjà converti
    existing = db.query(GuestConversion).filter(
        GuestConversion.ip_address == client_ip
    ).first()

    if existing:
        logger.warning(f"⚠️ IP {client_ip} already used free trial")
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
    - Détecte les PDFs scannés
    - Enregistre automatiquement dans failed_conversions si incompatible
    - Envoie notification Discord (sauf pour les scans)
    - Convertit si compatible
    """
    logger.info("=" * 80)
    logger.info(f"📤 UPLOAD REÇU: {file.filename} par {email}")
    logger.info("=" * 80)

    if file.content_type != 'application/pdf':
        raise HTTPException(status_code=400, detail="Seuls les fichiers PDF sont acceptés")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Lire le fichier
    pdf_bytes = await file.read()

    try:
        # === VALIDATION AUTOMATIQUE ===
        text = extract_text_from_pdf(pdf_bytes)
        validation_result = validate_statement(text)

        logger.info(f"🔍 Validation result: compatible={validation_result['compatible']}, bank={validation_result.get('bank')}")

        if not validation_result['compatible']:
            error_type = validation_result.get('error_type', 'UNKNOWN')
            logger.warning(f"⚠️ PDF non compatible: {error_type} - {file.filename} par {user.email}")

            # === Gestion selon le type d'erreur ===

            # NE PAS enregistrer les PDFs scannés (trop nombreux, pas utile)
            if error_type != 'SCANNED_PDF':
                # Encoder le PDF en base64
                pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')

                # Insérer dans la base de données
                failed_conversion = FailedConversion(
                    user_id=user.id,
                    user_email=user.email,
                    filename=file.filename,
                    bank_name=validation_result.get('bank', 'Inconnue'),
                    error_message=f"[{error_type}] {validation_result['message'][:500]}",
                    user_comment="Enregistrement automatique lors de l'upload",
                    file_content=pdf_base64,
                    reported_at=datetime.now(timezone.utc),
                    status='pending'
                )

                db.add(failed_conversion)
                db.commit()
                db.refresh(failed_conversion)

                logger.info(f"💾 Failed conversion enregistrée: ID={failed_conversion.id}")

                # === NOTIFICATION DISCORD uniquement pour banques non supportées ===
                if error_type == 'BANK_NOT_SUPPORTED':
                    await send_discord_notification({
                        'id': failed_conversion.id,
                        'filename': failed_conversion.filename,
                        'user_email': failed_conversion.user_email,
                        'bank_name': failed_conversion.bank_name,
                        'error_message': failed_conversion.error_message,
                        'reported_at': failed_conversion.reported_at
                    })
                    logger.info(f"📧 Notification Discord envoyée")
            else:
                logger.info(f"⏭️ PDF scanné ignoré (non enregistré)")

            # Retourner l'erreur au frontend avec message détaillé
            return UploadResponse(
                upload_id=None,
                status="error",
                transactions_count=0,
                bank_detected=validation_result.get('bank', 'UNKNOWN'),
                message=validation_result['message'],
                error=error_type,
                error_type=error_type,  # ✅ NOUVEAU CHAMP
                supported_banks=validation_result.get('supported_banks', {}),
                can_report=error_type != 'SCANNED_PDF'  # Pas de signalement pour les scans
            )

        bank_type = validation_result['bank']
        logger.info(f"✅ Validation réussie: {bank_type}")

    except Exception as e:
        logger.error(f"❌ Validation error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Erreur de validation: {str(e)}")

    # === SI COMPATIBLE: Vérifier les limites d'utilisation ===
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

    limits = {
        'free': 5,
        'premium': 50,
        'pro': None  # Illimité
    }

    user_limit = limits.get(user.subscription_tier, 5)

    if user_limit and usage.uploads_count >= user_limit:
        logger.warning(f"⚠️ Limite atteinte pour {email}: {usage.uploads_count}/{user_limit}")
        raise HTTPException(
            status_code=403,
            detail=f"Limite de {user_limit} uploads atteinte ce mois-ci. Passez Premium pour continuer !"
        )

    # === EXTRACTION avec le bon parser ===
    logger.info(f"🔄 Extraction des transactions...")
    transactions, _ = extract_from_pdf(pdf_bytes, enable_debug=False)

    if not transactions or len(transactions) == 0:
        logger.error(f"❌ Aucune transaction extraite du PDF")
        raise HTTPException(
            status_code=400, 
            detail="Aucune transaction trouvée dans ce relevé. Vérifiez le format du PDF."
        )

    logger.info(f"✅ {len(transactions)} transactions extraites")

    # === GÉNÉRATION DU FICHIER EXCEL ===
    excel_bytes = generate_excel(transactions)

    if not excel_bytes:
        logger.error(f"❌ Erreur génération Excel")
        raise HTTPException(status_code=400, detail="Erreur lors de la génération du fichier Excel")

    # === SAUVEGARDER dans la base de données ===
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

    logger.info("=" * 80)
    logger.info(f"✅ CONVERSION RÉUSSIE")
    logger.info(f"   User: {email}")
    logger.info(f"   Bank: {bank_type}")
    logger.info(f"   Transactions: {len(transactions)}")
    logger.info(f"   Usage: {usage.uploads_count}/{user_limit if user_limit else '∞'}")
    logger.info("=" * 80)

    return UploadResponse(
        upload_id=str(new_upload.id),
        status="success",
        transactions_count=len(transactions),
        bank_detected=bank_type,
        message=f"✅ {len(transactions)} transactions extraites avec succès ! ({usage.uploads_count}/{user_limit if user_limit else '∞'} ce mois)"
    )

# ============================================================================
# ENDPOINTS - VALIDATION
# ============================================================================

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
            transaction_count = count_transactions(text, validation_result['bank'])
            validation_result['estimated_transactions'] = transaction_count

        logger.info(
            f"🔍 Validation statement - User: {email}, "
            f"Bank: {validation_result.get('bank', 'UNKNOWN')}, "
            f"Compatible: {validation_result['compatible']}"
        )

        return validation_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error validating statement: {str(e)}")
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

        pdf_bytes = await file.read()
        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')

        report = FailedConversion(
            user_id=user.id,
            user_email=user.email,
            filename=file.filename,
            bank_name=bank_name or "Non spécifié",
            error_message=f"Signalement manuel: {user_comment or 'Aucun commentaire'}",
            user_comment=user_comment,
            file_content=pdf_base64,
            reported_at=datetime.now(timezone.utc),
            status='pending'
        )

        db.add(report)
        db.commit()
        db.refresh(report)

        # Notification Discord
        await send_discord_notification({
            'id': report.id,
            'filename': report.filename,
            'user_email': report.user_email,
            'bank_name': report.bank_name,
            'error_message': f"Signalement manuel: {user_comment}",
            'reported_at': report.reported_at
        })

        logger.info(f"📝 Failed conversion reported manually - User: {user.email}, Bank: {bank_name}, File: {file.filename}")

        return {
            "success": True,
            "message": "Merci pour votre signalement ! Nous allons analyser ce relevé et ajouter le support de votre banque prochainement."
        }

    except Exception as e:
        logger.error(f"❌ Error reporting failed conversion: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors du signalement")

# ============================================================================
# ENDPOINTS - DOWNLOAD & HISTORY
# ============================================================================

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

    limits = {
        'free': 5,
        'premium': 50,
        'pro': None
    }

    return {
        "uploads_count": usage.uploads_count if usage else 0,
        "limit": limits.get(user.subscription_tier, 5),
        "plan": user.subscription_tier,
        "month": today.month,
        "year": today.year
    }

# ============================================================================
# ENDPOINTS - ADMIN
# ============================================================================

@app.get("/admin/failed-conversions")
async def get_failed_conversions(
    status: str = "pending",
    limit: int = 50,
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Liste des relevés signalés (admin only)"""
    # TODO: Ajouter vérification admin avec un champ 'role' dans User

    reports = db.query(FailedConversion) \
        .filter(FailedConversion.status == status) \
        .order_by(FailedConversion.reported_at.desc()) \
        .limit(limit) \
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

    pdf_bytes = base64.b64decode(report.file_content)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{report.filename}"'}
    )

@app.get("/admin/pdf-downloader", response_class=HTMLResponse)
async def pdf_downloader_interface():
    """Interface web pour télécharger les PDFs échoués"""
    html_content = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ComptaFlow - Télécharger PDFs échoués</title>
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
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .subtitle { color: #666; margin-bottom: 30px; }
        .login-section, .pdfs-section { margin-bottom: 30px; }
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
        button:hover { background: #5568d3; transform: translateY(-2px); }
        button:disabled { background: #ccc; cursor: not-allowed; transform: none; }
        .pdf-item {
            background: #f8f9fa;
            padding: 16px;
            margin: 12px 0;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .pdf-item h3 { color: #333; margin-bottom: 8px; font-size: 18px; }
        .pdf-info { color: #666; font-size: 14px; margin: 4px 0; }
        .pdf-item button { margin-top: 12px; width: auto; padding: 10px 24px; }
        .error { background: #fee; color: #c33; padding: 12px; border-radius: 8px; margin: 12px 0; }
        .success { background: #efe; color: #3a3; padding: 12px; border-radius: 8px; margin: 12px 0; }
        .loading { text-align: center; padding: 20px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 ComptaFlow Admin</h1>
        <p class="subtitle">Télécharger les PDFs des conversions échouées</p>

        <!-- Section Login -->
        <div class="login-section" id="loginSection">
            <input type="email" id="email" placeholder="Email" value="manidelavega@gmail.com">
            <input type="password" id="password" placeholder="Password" value="">
            <button onclick="login()">Se connecter</button>
            <div id="loginError"></div>
        </div>

        <!-- Section PDFs -->
        <div class="pdfs-section hidden" id="pdfsSection">
            <button onclick="loadPDFs()">🔄 Actualiser la liste</button>
            <div id="pdfsList"></div>
        </div>
    </div>

    <script>
        const API_URL = window.location.origin;
        let token = '';

        async function login() {
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const errorDiv = document.getElementById('loginError');

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
                        pdfsList.innerHTML = '<div class="success">✅ Aucun PDF en attente !</div>';
                        return;
                    }

                    pdfsList.innerHTML = data.reports.map(pdf => `
                        <div class="pdf-item">
                            <h3>📄 ${pdf.filename}</h3>
                            <div class="pdf-info">👤 Utilisateur: ${pdf.user_email}</div>
                            <div class="pdf-info">🏦 Banque: ${pdf.bank_name || 'Inconnue'}</div>
                            <div class="pdf-info">📅 Date: ${new Date(pdf.reported_at).toLocaleString('fr-FR')}</div>
                            <div class="pdf-info">❌ Erreur: ${pdf.error_message}</div>
                            <button onclick="downloadPDF(${pdf.id}, '${pdf.filename}')">⬇️ Télécharger</button>
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

# ============================================================================
# ENDPOINTS - STRIPE
# ============================================================================

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

    plan = request.get('plan')
    prices = {
        'premium': os.getenv('STRIPE_PRICE_PREMIUM'),
        'pro': os.getenv('STRIPE_PRICE_PRO')
    }

    if plan not in prices or not prices[plan]:
        raise HTTPException(status_code=400, detail="Invalid plan or price not configured")

    try:
        session = stripe.checkout.Session.create(
            customer_email=user.email,
            payment_method_types=['card'],
            line_items=[{
                'price': prices[plan],
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:5173')}/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{os.getenv('FRONTEND_URL', 'http://localhost:5173')}/pricing",
            metadata={
                'user_id': str(user.id),
                'user_email': user.email,
                'plan': plan
            }
        )

        return {"url": session.url, "session_id": session.id}

    except Exception as e:
        logger.error(f"❌ Stripe error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

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


# ============================================================================
# SUPPORT - CONTACT FORM
# ============================================================================

class SupportContactRequest(BaseModel):
    subject: str
    message: str

# ============================================================================
# SUPPORT - DISCORD NOTIFICATION
# ============================================================================

async def send_discord_support_message(support_data: dict):
    """
    Envoie un message de support vers Discord
    """
    DISCORD_WEBHOOK_URL = os.getenv('DISCORD_WEBHOOK_URL')
    
    if not DISCORD_WEBHOOK_URL:
        logger.warning("⚠️ Discord webhook non configuré")
        return
    
    # Créer l'embed
    embed = {
        "embeds": [{
            "title": "💬 Nouveau message de support",
            "description": "Un utilisateur a envoyé un message via le formulaire de contact",
            "color": 5793266,  # Bleu
            "fields": [
                {
                    "name": "👤 Utilisateur",
                    "value": support_data['user_email'],
                    "inline": True
                },
                {
                    "name": "📋 Plan",
                    "value": support_data['subscription_tier'].upper(),
                    "inline": True
                },
                {
                    "name": "📌 Sujet",
                    "value": support_data['subject'][:256],
                    "inline": False
                },
                {
                    "name": "💬 Message",
                    "value": support_data['message'][:1024] if len(support_data['message']) <= 1024 else support_data['message'][:1021] + "...",
                    "inline": False
                }
            ],
            "footer": {
                "text": "ComptaFlow - Support"
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(DISCORD_WEBHOOK_URL, json=embed) as resp:
                if resp.status == 204:
                    logger.info(f"✅ Message de support envoyé sur Discord pour {support_data['user_email']}")
                else:
                    error_text = await resp.text()
                    logger.error(f"❌ Erreur Discord webhook: status {resp.status}: {error_text}")
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'envoi Discord: {str(e)}")

# ============================================================================
# SUPPORT - ENDPOINT
# ============================================================================


@app.post("/support/contact")
async def support_contact(
    request: SupportContactRequest,
    email: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Endpoint pour recevoir les messages du formulaire de support
    Envoie une notification Discord
    """
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    logger.info(f"📧 Support message from {email}: {request.subject}")
    
    # Préparer les données pour Discord
    support_data = {
        'user_email': user.email,
        'user_name': user.full_name or 'Non renseigné',
        'subscription_tier': user.subscription_tier,
        'subject': request.subject,
        'message': request.message
    }
    
    # Envoyer la notification Discord
    await send_discord_support_message(support_data)
    
    # TODO (optionnel) : Enregistrer le message en base de données
    # support_ticket = SupportTicket(
    #     user_id=user.id,
    #     subject=request.subject,
    #     message=request.message,
    #     status='pending',
    #     created_at=datetime.now(timezone.utc)
    # )
    # db.add(support_ticket)
    # db.commit()
    
    return {
        "success": True,
        "message": "Message reçu ! Notre équipe vous répondra sous 24h."
    }



# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/health")
async def health():
    """Health check"""
    return {"status": "ok", "version": "2.0.0"}

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "ComptaFlow",
        "version": "2.0.0",
        "status": "running",
        "features": ["auth", "upload", "validation", "discord_notifications"]
    }
    

#TEST#
@app.get("/test-logs")
async def test_logs():
    """Endpoint de test pour vérifier que les logs fonctionnent"""
    logger.info("🧪 TEST LOG INFO")
    logger.warning("⚠️ TEST LOG WARNING")
    logger.error("❌ TEST LOG ERROR")
    logger.debug("🔍 TEST LOG DEBUG (visible seulement si level=DEBUG)")
    
    return {"status": "Logs envoyés - Vérifiez la console Render"}


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
