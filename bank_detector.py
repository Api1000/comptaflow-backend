#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
COMPTAFLOW - Détection et validation automatique des relevés bancaires
VERSION PERMISSIVE avec support étendu pour LCL

Supporte : LCL, Crédit Agricole, Banque Populaire
"""

import re
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

# ============================================================================
# SIGNATURES DES BANQUES SUPPORTÉES
# ============================================================================

BANK_SIGNATURES = {
    'LCL': {
        'keywords': [
            'CREDIT LYONNAIS', 
            'LCL', 
            'LCL.FR', 
            'CRLYFRPP', 
            'RELEVE DE COMPTE COURANT',
            'PAIEMENTS PAR CARTE'
        ],
        'date_patterns': [
            r'LE\s+\d{1,2}/\d{1,2}',      # LE 30/10 (FORMAT PRINCIPAL)
            r'\d{2}\.\d{2}\.\d{2}',      # 05.09.25
            r'\d{2}\.\d{2}',               # 05.09
            r'\d{1,2}/\d{1,2}/\d{4}',     # 30/10/2025
        ],
        'amount_pattern': r'\d{1,5}[,\.]\d{2}',  # Format permissif: 16,62 ou 16.62
        'columns': ['DATE', 'LIBELLE', 'VALEUR', 'DEBIT', 'CREDIT'],  # Optionnel
        'description': 'LCL - Crédit Lyonnais',
        'required_keywords': 1,  # Au moins 1 keyword suffit
        'strict_validation': False  # Validation permissive
    },

    'CREDIT_AGRICOLE': {
        'keywords': [
            'CREDIT AGRICOLE', 
            'CA-TOULOUSE31.FR', 
            'CAISSE REGIONALE'
        ],
        'date_patterns': [
            r'\d{2}\.\d{2}',              # 06.11
            r'\d{2}/\d{2}/\d{4}',         # 06/11/2025
        ],
        'amount_pattern': r'\d{1,3}(,\d{3})*\.\d{2}\s*€?',  # 100,11 € ou 12.00
        'columns': ['Date achat', 'Commerce', 'Montant'],
        'description': 'Crédit Agricole',
        'required_keywords': 1,
        'strict_validation': True
    },

    'BANQUE_POPULAIRE': {
        'keywords': [
            'BANQUE POPULAIRE', 
            'BANQUEPOPULAIRE.FR', 
            'BPOC.FR'
        ],
        'date_patterns': [
            r'\d{2}/\d{2}/\d{2}',         # 30/10/25
            r'\d{2}/\d{2}/\d{4}',         # 30/10/2025
        ],
        'amount_pattern': r'\d{1,3}(\s\d{3})*,\d{2}\s*€',  # 2,70 €
        'columns': ["DATE DE L\'ACHAT", 'COMMERCANT', 'MONTANT'],
        'description': 'Banque Populaire',
        'required_keywords': 1,
        'strict_validation': True
    }
}


# ============================================================================
# DÉTECTION DE LA BANQUE
# ============================================================================

def detect_bank(text: str) -> Optional[str]:
    """
    Détecte automatiquement la banque à partir du texte du relevé

    Args:
        text: Texte extrait du PDF

    Returns:
        Nom de la banque ('LCL', 'CREDIT_AGRICOLE', etc.) ou None
    """
    text_upper = text.upper()

    # Compteur de score pour chaque banque
    scores = {}

    for bank_name, signature in BANK_SIGNATURES.items():
        score = 0
        keywords_found = []

        for keyword in signature['keywords']:
            if keyword in text_upper:
                score += 1
                keywords_found.append(keyword)

        scores[bank_name] = score

        if score > 0:
            logger.info(f"   {bank_name}: {score} keyword(s) trouvé(s) - {keywords_found}")

    # Retourne la banque avec le meilleur score (si > 0)
    if scores and max(scores.values()) > 0:
        detected_bank = max(scores, key=scores.get)
        logger.info(f"🏦 Banque détectée: {detected_bank}")
        return detected_bank

    logger.warning("⚠️ Aucune banque reconnue")
    return None


# ============================================================================
# VALIDATION DU FORMAT
# ============================================================================

def validate_format(text: str, bank_name: str) -> Tuple[bool, str, Dict]:
    """
    Vérifie si le format du relevé est compatible avec la banque détectée
    VERSION PERMISSIVE pour LCL

    Args:
        text: Texte extrait du PDF
        bank_name: Nom de la banque détectée

    Returns:
        Tuple (est_valide, message, détails)
    """
    if bank_name not in BANK_SIGNATURES:
        return False, "Banque non supportée", {}

    signature = BANK_SIGNATURES[bank_name]
    strict = signature.get('strict_validation', True)

    details = {
        'bank': bank_name,
        'bank_description': signature['description'],
        'expected_columns': signature['columns'],
        'strict_mode': strict
    }

    logger.info(f"\n🔍 Validation du format {signature['description']} (strict={strict})")

    # === ÉTAPE 1: Vérifier les patterns de date ===
    date_found = False
    matched_patterns = []

    for pattern in signature['date_patterns']:
        matches = re.findall(pattern, text)
        if matches:
            date_found = True
            matched_patterns.append(pattern)
            logger.info(f"   ✅ Pattern de date trouvé: {pattern} ({len(matches)} occurrences)")

    if not date_found:
        logger.warning(f"   ❌ Aucun pattern de date trouvé")
        if strict:
            return False, f"Format de date incompatible pour {signature['description']}", details
    else:
        details['date_patterns_matched'] = matched_patterns

    # === ÉTAPE 2: Vérifier le pattern de montant ===
    amount_matches = re.findall(signature['amount_pattern'], text)

    if not amount_matches:
        logger.warning(f"   ❌ Aucun montant trouvé avec le pattern {signature['amount_pattern']}")
        if strict:
            return False, f"Format de montant incompatible pour {signature['description']}", details
    else:
        logger.info(f"   ✅ {len(amount_matches)} montant(s) trouvé(s)")
        details['amount_pattern_matched'] = True
        details['amount_count'] = len(amount_matches)

    # === ÉTAPE 3: Vérifier les colonnes (optionnel si non strict) ===
    columns_found = []
    for column in signature['columns']:
        if column.upper() in text.upper():
            columns_found.append(column)

    details['columns_found'] = columns_found
    details['columns_missing'] = [col for col in signature['columns'] if col not in columns_found]

    columns_ratio = len(columns_found) / len(signature['columns']) if signature['columns'] else 1.0
    logger.info(f"   {'✅' if columns_ratio >= 0.5 else '⚠️'} Colonnes: {len(columns_found)}/{len(signature['columns'])} trouvées")

    # === DÉCISION FINALE ===
    if strict:
        # Mode strict : au moins 50% des colonnes requises
        if columns_ratio >= 0.5:
            logger.info(f"   ✅ VALIDATION RÉUSSIE (mode strict)")
            return True, f"✅ Relevé {signature['description']} compatible et prêt pour conversion", details
        else:
            logger.warning(f"   ❌ VALIDATION ÉCHOUÉE (mode strict)")
            return False, f"❌ Structure du relevé {signature['description']} non reconnue", details
    else:
        # Mode permissif : date OU montant suffit
        if date_found or amount_matches:
            logger.info(f"   ✅ VALIDATION RÉUSSIE (mode permissif)")
            return True, f"✅ Relevé {signature['description']} compatible et prêt pour conversion", details
        else:
            logger.warning(f"   ❌ VALIDATION ÉCHOUÉE (mode permissif)")
            return False, f"❌ Aucune transaction détectable dans le relevé", details


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def get_supported_banks() -> Dict[str, str]:
    """
    Retourne la liste des banques supportées avec leur description

    Returns:
        Dict {code_banque: description}
    """
    return {
        bank_code: signature['description']
        for bank_code, signature in BANK_SIGNATURES.items()
    }


def count_transactions(text: str, bank_name: str) -> int:
    """
    Compte le nombre approximatif de transactions dans le relevé

    Args:
        text: Texte du relevé
        bank_name: Banque détectée

    Returns:
        Nombre estimé de transactions
    """
    if bank_name not in BANK_SIGNATURES:
        return 0

    signature = BANK_SIGNATURES[bank_name]

    # Stratégie 1 : Compter les patterns de date
    date_count = 0
    for pattern in signature['date_patterns']:
        matches = re.findall(pattern, text)
        date_count = max(date_count, len(matches))

    # Stratégie 2 : Compter les montants
    amount_matches = re.findall(signature['amount_pattern'], text)
    # Filtrer les montants suspects (0,00, TOTAL, etc.)
    valid_amounts = [
        m for m in amount_matches 
        if '0,00' not in m and '0.00' not in m
    ]

    # Prendre le minimum des deux (plus conservateur)
    estimated = min(date_count, len(valid_amounts)) if date_count > 0 else len(valid_amounts)

    logger.info(f"📊 Estimation: {estimated} transactions (dates={date_count}, montants={len(valid_amounts)})")

    return estimated


# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

def validate_statement(text: str) -> Dict:
    """
    Fonction principale : détecte et valide un relevé bancaire
    VERSION PERMISSIVE

    Args:
        text: Texte extrait du PDF

    Returns:
        Dict avec toutes les informations de validation
    """
    logger.info("=" * 80)
    logger.info("🔍 VALIDATION DU RELEVÉ BANCAIRE")
    logger.info("=" * 80)

    # === ÉTAPE 1: Détection de la banque ===
    bank_name = detect_bank(text)

    if not bank_name:
        logger.warning("❌ Banque non reconnue")
        return {
            'compatible': False,
            'bank': 'UNKNOWN',
            'bank_description': 'Banque non reconnue',
            'message': "❌ Cette banque n'est pas encore supportée. Signalez-nous ce relevé pour que nous l'ajoutions !",
            'supported_banks': get_supported_banks(),
            'suggestion': 'Banques actuellement supportées : LCL, Crédit Agricole, Banque Populaire'
        }

    # === ÉTAPE 2: Validation du format ===
    is_valid, message, details = validate_format(text, bank_name)

    logger.info("=" * 80)
    logger.info(f"{'✅ VALIDATION RÉUSSIE' if is_valid else '❌ VALIDATION ÉCHOUÉE'}")
    logger.info("=" * 80)

    return {
        'compatible': is_valid,
        'bank': bank_name,
        'bank_description': details.get('bank_description', ''),
        'message': message,
        'details': details,
        'supported_banks': get_supported_banks()
    }
