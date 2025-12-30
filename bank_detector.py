"""
Système de détection et validation automatique des relevés bancaires
Supporte : LCL, Crédit Agricole, Banque Populaire
"""
import re
from typing import Dict, Tuple, Optional

# Signatures des banques supportées
BANK_SIGNATURES = {
    'LCL': {
        'keywords': ['CREDIT LYONNAIS', 'LCL.FR', 'CRLYFRPP', 'RELEVE DE COMPTE COURANT'],
        'date_patterns': [
            r'\d{2}\.\d{2}\.\d{2}',  # 05.09.25
            r'\d{2}\.\d{2}'            # 05.09
        ],
        'amount_pattern': r'\d{1,3}(\s\d{3})*,\d{2}',  # 1 500,00
        'columns': ['DATE', 'LIBELLE', 'VALEUR', 'DEBIT', 'CREDIT'],
        'description': 'LCL - Crédit Lyonnais'
    },
    'CREDIT_AGRICOLE': {
        'keywords': ['CREDIT AGRICOLE', 'CA-TOULOUSE31.FR', 'CAISSE REGIONALE'],
        'date_patterns': [
            r'\d{2}\.\d{2}',           # 06.11
            r'\d{2}/\d{2}/\d{4}'      # 06/11/2025
        ],
        'amount_pattern': r'\d{1,3}(,\d{3})*\.\d{2}\s*€?',  # 100,11 € ou 12.00
        'columns': ['Date achat', 'Commerce', 'Montant'],
        'description': 'Crédit Agricole'
    },
    'BANQUE_POPULAIRE': {
        'keywords': ['BANQUE POPULAIRE', 'BANQUEPOPULAIRE.FR', 'BPOC.FR'],
        'date_patterns': [
            r'\d{2}/\d{2}/\d{2}',     # 30/10/25
            r'\d{2}/\d{2}/\d{4}'      # 30/10/2025
        ],
        'amount_pattern': r'\d{1,3}(\s\d{3})*,\d{2}\s*€',  # 2,70 €
        'columns': ["DATE DE L\\'ACHAT", 'COMMERCANT', 'MONTANT'],
        'description': 'Banque Populaire'
    }
}


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
        for keyword in signature['keywords']:
            if keyword in text_upper:
                score += 1
        scores[bank_name] = score

    # Retourne la banque avec le meilleur score (si > 0)
    if max(scores.values()) > 0:
        return max(scores, key=scores.get)

    return None


def validate_format(text: str, bank_name: str) -> Tuple[bool, str, Dict]:
    """
    Vérifie si le format du relevé est compatible avec la banque détectée

    Args:
        text: Texte extrait du PDF
        bank_name: Nom de la banque détectée

    Returns:
        Tuple (est_valide, message, détails)
    """
    if bank_name not in BANK_SIGNATURES:
        return False, "Banque non supportée", {}

    signature = BANK_SIGNATURES[bank_name]
    details = {
        'bank': bank_name,
        'bank_description': signature['description'],
        'expected_columns': signature['columns']
    }

    # Vérifie si au moins un pattern de date est présent
    date_found = False
    for pattern in signature['date_patterns']:
        if re.search(pattern, text):
            date_found = True
            details['date_pattern_matched'] = pattern
            break

    if not date_found:
        return False, f"Format de date incompatible pour {signature['description']}", details

    # Vérifie si le pattern de montant est présent
    amount_found = re.search(signature['amount_pattern'], text)
    if not amount_found:
        return False, f"Format de montant incompatible pour {signature['description']}", details

    details['amount_pattern_matched'] = True

    # Vérifie si les colonnes attendues sont présentes
    columns_found = []
    for column in signature['columns']:
        if column.upper() in text.upper():
            columns_found.append(column)

    details['columns_found'] = columns_found
    details['columns_missing'] = [col for col in signature['columns'] if col not in columns_found]

    # Considère le format valide si au moins 50% des colonnes sont trouvées
    if len(columns_found) >= len(signature['columns']) / 2:
        return True, f"✅ Relevé {signature['description']} compatible et prêt pour conversion", details
    else:
        return False, f"❌ Structure du relevé {signature['description']} non reconnue", details


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


def validate_statement(text: str) -> Dict:
    """
    Fonction principale : détecte et valide un relevé bancaire

    Args:
        text: Texte extrait du PDF

    Returns:
        Dict avec toutes les informations de validation
    """
    # Détection de la banque
    bank_name = detect_bank(text)

    if not bank_name:
        return {
            'compatible': False,
            'bank': 'UNKNOWN',
            'bank_description': 'Banque non reconnue',
            'message': "❌ Cette banque n'est pas encore supportée",
            'supported_banks': get_supported_banks(),
            'suggestion': 'Banques actuellement supportées : LCL, Crédit Agricole, Banque Populaire'
        }

    # Validation du format
    is_valid, message, details = validate_format(text, bank_name)

    return {
        'compatible': is_valid,
        'bank': bank_name,
        'bank_description': details.get('bank_description', ''),
        'message': message,
        'details': details,
        'supported_banks': get_supported_banks()
    }


# Fonction utilitaire pour extraire les transactions (à implémenter selon vos parsers)
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

    # Compte le nombre de patterns de montant trouvés
    matches = re.findall(signature['amount_pattern'], text)

    # Filtre les montants trop petits ou suspects (< 0.01€)
    valid_matches = [m for m in matches if '0,00' not in m and '0.00' not in m]

    return len(valid_matches)
