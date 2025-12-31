#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COMPTAFLOW - Module de Parsing Bancaire
Extraction et parsing de relevés bancaires PDF
"""

import pdfplumber
import pandas as pd
import re
import io
import logging
from typing import List, Dict, Tuple
import PyPDF2
from io import BytesIO
from fastapi import HTTPException

logger = logging.getLogger(__name__)


# ============================================================================
# EXTRACTION PDF
# ============================================================================

def extract_text_from_pdf(file_content: bytes) -> str:
    """Extrait le texte d'un fichier PDF"""
    try:
        pdf_reader = PyPDF2.PdfReader(BytesIO(file_content))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text()
        return text
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Erreur lors de la lecture du PDF: {str(e)}"
        )


# ============================================================================
# DÉTECTION BANQUE
# ============================================================================

def detect_bank_format(text: str) -> str:
    """Détecte le format bancaire"""
    text_upper = text.upper()
    
    if "CREDIT AGRICOLE" in text_upper:
        return "CA"
    elif "BANQUE POPULAIRE" in text_upper:
        return "BP"
    elif "CREDIT LYONNAIS" in text_upper or "LCL" in text_upper:
        return "LCL"
    elif "SOCIETE GENERALE" in text_upper or "SOCIÉTÉ GÉNÉRALE" in text_upper:
        return "SG"
    elif "BNP" in text_upper:
        return "BNP"
    else:
        return "UNKNOWN"


# ============================================================================
# PARSERS BANCAIRES
# ============================================================================

def extract_ca_transactions(lines: List[str]) -> List[Dict]:
    """
    Format Crédit Agricole: JJ.MM COMMERCE LIEU MONTANT
    """
    transactions = []
    skip_keywords = ['TOTAL', 'Date', 'Montant', 'Commerce', 'Page']
    
    for line in lines:
        # Ignorer les lignes d'en-tête
        if any(skip in line for skip in skip_keywords):
            continue
        
        # Pattern: date au format JJ.MM
        date_match = re.search(r'(\d{1,2}\.\d{2})', line)
        # Pattern: montant au format -?X,XX ou -?X.XXX,XX
        montant_match = re.search(r'-?(\d{1,5}),(\d{2})', line)
        
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
    """
    Format Banque Populaire: JJMMYY COMMERCE ADRESSE MONTANT
    """
    transactions = []
    skip_keywords = ['DATE', 'NOM', 'MONTANT', 'Page', 'TOTAL']
    
    for line in lines:
        if any(skip in line for skip in skip_keywords):
            continue
        
        # Pattern: JJMMYY au début de la ligne
        date_match = re.match(r'(\d{1,2})(\d{2})(\d{2})', line.strip())
        # Pattern: montant avec virgule
        montant_match = re.search(r'(\d+),(\d{2})', line.strip())
        
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
    """
    Format LCL - PAIEMENTS PAR CARTE
    Gère deux formats:
    1. Format classique: "LIBELLE LE JJ/MM MONTANT" (sur une ligne)
    2. Format scanné: "LIBELLE LE JJ/MM" sur une ligne, "MONTANT" sur la suivante
    """
    transactions = []
    
    # Dictionnaire des mois
    mois_dict = {
        'JANVIER': '01', 'FÉVRIER': '02', 'FEVRIER': '02',
        'MARS': '03', 'AVRIL': '04', 'MAI': '05', 'JUIN': '06',
        'JUILLET': '07', 'AOÛT': '08', 'AOUT': '08',
        'SEPTEMBRE': '09', 'OCTOBRE': '10', 'NOVEMBRE': '11',
        'DÉCEMBRE': '12', 'DECEMBRE': '12'
    }
    
    annee = None
    mois_num = None
    
    # Extraire mois et année du titre
    for line in lines:
        match = re.search(r"PAIEMENTS PAR CARTE D[E']?\s*([A-ZÉÈÊÀÙ]+)\s+(\d{4})", line)
        if match:
            mois_txt = match.group(1).upper()
            annee = match.group(2)
            mois_num = mois_dict.get(mois_txt, None)
            logger.info(f"📅 Relevé LCL détecté: {mois_txt} {annee} (mois={mois_num})")
            break
    
    if not annee:
        annee = '2025'
        logger.warning("⚠️ Année non détectée, utilisation de 2025 par défaut")
    
    in_card_section = False
    skip_keywords = [
        'PAIEMENTS', 'TOTAL', 'MONTANT', 'CARTE', 'RELEVE', 
        'SOUS TOTAL', 'LIBELLE', 'VALEUR', 'DEBIT', 'CREDIT',
        'Page', 'Crédit Lyonnais', 'SIREN', 'RCS', 'ORIAS'
    ]
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Activer le parsing
        if 'PAIEMENTS PAR CARTE' in line:
            in_card_section = True
            i += 1
            continue
        
        # Désactiver si nouvel en-tête
        if in_card_section and 'RELEVE DE COMPTE' in line and 'PAIEMENTS' not in line:
            in_card_section = False
            i += 1
            continue
        
        if not in_card_section or not line:
            i += 1
            continue
        
        # Ignorer les lignes d'en-tête
        if any(skip in line for skip in skip_keywords):
            i += 1
            continue
        
        # Chercher le pattern "LE JJ/MM" dans la ligne
        date_match = re.search(r'LE\s+(\d{1,2})/(\d{1,2})', line)
        
        if date_match:
            jour = date_match.group(1).zfill(2)
            mois = date_match.group(2).zfill(2)
            libelle = line.strip()
            
            # Extraire l'année correcte (gestion cross-mois)
            if mois_num and int(mois) < int(mois_num):
                annee_trans = annee
            elif mois_num and int(mois) > int(mois_num):
                if int(mois_num) == 12 and int(mois) == 1:
                    annee_trans = str(int(annee) - 1)
                else:
                    annee_trans = annee
            else:
                annee_trans = annee
            
            date_format = f"{jour}/{mois}/{annee_trans}"
            
            # CASE 1: Montant sur la MÊME ligne
            montant_same_line = re.search(r'(\d{1,}[,\.]\d{2})\s*$', line)
            
            if montant_same_line:
                try:
                    montant = float(montant_same_line.group(1).replace(',', '.'))
                    # Retirer le montant du libellé
                    libelle = line[:montant_same_line.start()].strip()
                    
                    if len(libelle) >= 3:
                        transactions.append({
                            'Date': date_format,
                            'Libellé': libelle,
                            'Montant': -montant
                        })
                        logger.debug(f"✅ Transaction (même ligne): {libelle} - {montant}€")
                except:
                    pass
            
            # CASE 2: Montant sur la ligne SUIVANTE
            elif i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                
                # Vérifier si la ligne suivante est un montant pur
                montant_next_line = re.match(r'^(\d{1,}[,\.]\d{2})$', next_line)
                
                if montant_next_line:
                    try:
                        montant = float(montant_next_line.group(1).replace(',', '.'))
                        
                        if len(libelle) >= 3:
                            transactions.append({
                                'Date': date_format,
                                'Libellé': libelle,
                                'Montant': -montant
                            })
                            logger.debug(f"✅ Transaction (ligne suivante): {libelle} - {montant}€")
                            i += 1  # Sauter la ligne du montant
                    except:
                        pass
        
        i += 1
    
    logger.info(f"✅ {len(transactions)} transactions LCL extraites")
    return transactions



# ============================================================================
# EXTRACTION PRINCIPALE
# ============================================================================

def extract_from_pdf(pdf_bytes: bytes) -> Tuple[List[Dict], str]:
    """
    Extrait transactions depuis PDF
    Retourne: (transactions, bank_type)
    """
    try:
        pdf_file = io.BytesIO(pdf_bytes)
        
        with pdfplumber.open(pdf_file) as pdf:
            text = ""
            for page in pdf.pages:
                text += page.extract_text()
        
        bank_type = detect_bank_format(text)
        
        lines = [l.strip() for l in text.split('\n') if l.strip()]
        
        # Parsing selon la banque
        if bank_type == "CA":
            transactions = extract_ca_transactions(lines)
        elif bank_type == "BP":
            transactions = extract_bp_transactions(lines)
        elif bank_type == "LCL":
            transactions = extract_lcl_transactions(lines)
        else:
            transactions = []
        
        return transactions, bank_type
        
    except Exception as e:
        logger.error(f"❌ Erreur extraction: {str(e)}")
        return [], "ERROR"


# ============================================================================
# GÉNÉRATION EXCEL
# ============================================================================

def generate_excel(transactions: List[Dict]) -> bytes:
    """Génère fichier Excel depuis transactions"""
    if not transactions:
        return None
    
    df = pd.DataFrame(transactions)
    
    # Convertir la colonne Date en datetime
    df['Date'] = pd.to_datetime(df['Date'], format='%d/%m/%Y', errors='coerce')
    
    # Supprimer les lignes avec dates invalides
    df = df.dropna(subset=['Date'])
    
    # Reformater la date
    df['Date'] = df['Date'].dt.strftime('%d/%m/%Y')
    
    if df.empty:
        return None
    
    # Créer le fichier Excel en mémoire
    output = io.BytesIO()
    
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df[['Date', 'Libellé', 'Montant']].to_excel(
            writer, 
            index=False, 
            sheet_name='Relevé'
        )
        
        # Ajuster les largeurs de colonnes
        ws = writer.sheets['Relevé']
        ws.column_dimensions['A'].width = 12  # Date
        ws.column_dimensions['B'].width = 50  # Libellé
        ws.column_dimensions['C'].width = 15  # Montant
    
    output.seek(0)
    return output.getvalue()
