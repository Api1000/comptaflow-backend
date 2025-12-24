#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests API - Penny Lane Converter
Run: pytest test_api.py -v
"""

import pytest
from fastapi.testclient import TestClient
import sys
sys.path.insert(0, '.')

from backend_main import app

client = TestClient(app)

# ============ TESTS HEALTH ============

def test_health():
    """Test health check"""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

# ============ TESTS AUTH ============

def test_register():
    """Test enregistrement"""
    response = client.post("/api/auth/register", json={
        "email": "test@example.com",
        "password": "SecurePass123!",
        "full_name": "Test User"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

def test_register_duplicate():
    """Test email en doublon"""
    email = "duplicate@example.com"
    
    # Premier enregistrement
    client.post("/api/auth/register", json={
        "email": email,
        "password": "Pass123!",
        "full_name": "User 1"
    })
    
    # Deuxième avec même email
    response = client.post("/api/auth/register", json={
        "email": email,
        "password": "Pass456!",
        "full_name": "User 2"
    })
    
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]

def test_login():
    """Test connexion"""
    # Enregistrer d'abord
    email = "login_test@example.com"
    password = "SecurePass123!"
    
    client.post("/api/auth/register", json={
        "email": email,
        "password": password,
        "full_name": "Login Test"
    })
    
    # Login
    response = client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

def test_login_wrong_password():
    """Test login avec mauvais password"""
    email = "wrong_pass@example.com"
    
    client.post("/api/auth/register", json={
        "email": email,
        "password": "CorrectPass123!",
        "full_name": "User"
    })
    
    response = client.post("/api/auth/login", json={
        "email": email,
        "password": "WrongPassword123!"
    })
    
    assert response.status_code == 401

# ============ TESTS UPLOAD ============

def test_upload_without_auth():
    """Test upload sans auth"""
    response = client.post(
        "/api/upload",
        files={"file": ("test.pdf", b"fake pdf", "application/pdf")}
    )
    assert response.status_code == 401

def test_upload_invalid_file_type():
    """Test upload fichier non-PDF"""
    # Enregistrer d'abord
    response = client.post("/api/auth/register", json={
        "email": "upload_test@example.com",
        "password": "Pass123!",
        "full_name": "Upload Tester"
    })
    token = response.json()["access_token"]
    
    # Essayer upload fichier non-PDF
    response = client.post(
        "/api/upload",
        files={"file": ("test.txt", b"text file", "text/plain")},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 400

# ============ TESTS HISTORY ============

def test_get_history():
    """Test récupération historique"""
    # Enregistrer
    response = client.post("/api/auth/register", json={
        "email": "history_test@example.com",
        "password": "Pass123!",
        "full_name": "History Tester"
    })
    token = response.json()["access_token"]
    
    # Récupérer historique
    response = client.get(
        "/api/history",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "uploads" in data
    assert isinstance(data["uploads"], list)

# ============ EXTRACTION TESTS ============

def test_detect_bank_ca():
    """Test détection Crédit Agricole"""
    from backend_main import detect_bank_format
    
    text = "CREDIT AGRICOLE\n03.09 CERTAS ESSOF007 COLOMIERS 106,13"
    assert detect_bank_format(text) == "CA"

def test_detect_bank_bp():
    """Test détection Banque Populaire"""
    from backend_main import detect_bank_format
    
    text = "BANQUE POPULAIRE\n30/10/25 CAPIO CROIX 2,70 €"
    assert detect_bank_format(text) == "BP"

def test_detect_bank_lcl():
    """Test détection LCL"""
    from backend_main import detect_bank_format
    
    text = "CREDIT LYONNAIS\nPAIEMENTS PAR CARTE DE SEPTEMBRE 2025"
    assert detect_bank_format(text) == "LCL"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
