"""
Tests unitaires pour bank_detector.py
"""
import sys
sys.path.append('..')
from bank_detector import detect_bank, validate_format, validate_statement

# Exemples de textes de relevés
LCL_SAMPLE = """
CREDIT LYONNAIS
www.LCL.fr
RELEVE DE COMPTE COURANT
DATE    LIBELLE    VALEUR    DEBIT    CREDIT
05.09   VIR INST   08.09.25  1 500,00
"""

CA_SAMPLE = """
CREDIT AGRICOLE TOULOUSE 31
www.ca-toulouse31.fr
Relevé Carte Business
Date achat    Commerce    Montant en Eur.
06.11         CARREFOUR   100,11
"""

BP_SAMPLE = """
BANQUE POPULAIRE OCCITANE
www.banquepopulaire.fr
Relevé mensuel
DATE DE L'ACHAT    COMMERCANT    MONTANT
30/10/25          CARREFOUR      2,70 €
"""

UNKNOWN_SAMPLE = """
Some random bank not supported
This is not a real bank statement
"""


def test_detect_lcl():
    """Test détection LCL"""
    bank = detect_bank(LCL_SAMPLE)
    assert bank == 'LCL', f"Expected 'LCL', got '{bank}'"
    print("✅ Test LCL detection passed")


def test_detect_ca():
    """Test détection Crédit Agricole"""
    bank = detect_bank(CA_SAMPLE)
    assert bank == 'CREDIT_AGRICOLE', f"Expected 'CREDIT_AGRICOLE', got '{bank}'"
    print("✅ Test CA detection passed")


def test_detect_bp():
    """Test détection Banque Populaire"""
    bank = detect_bank(BP_SAMPLE)
    assert bank == 'BANQUE_POPULAIRE', f"Expected 'BANQUE_POPULAIRE', got '{bank}'"
    print("✅ Test BP detection passed")


def test_detect_unknown():
    """Test banque inconnue"""
    bank = detect_bank(UNKNOWN_SAMPLE)
    assert bank is None, f"Expected None, got '{bank}'"
    print("✅ Test unknown bank passed")


def test_validate_lcl():
    """Test validation LCL"""
    is_valid, message, details = validate_format(LCL_SAMPLE, 'LCL')
    assert is_valid, f"LCL should be valid. Message: {message}"
    print("✅ Test LCL validation passed")


def test_validate_ca():
    """Test validation CA"""
    is_valid, message, details = validate_format(CA_SAMPLE, 'CREDIT_AGRICOLE')
    assert is_valid, f"CA should be valid. Message: {message}"
    print("✅ Test CA validation passed")


def test_validate_bp():
    """Test validation BP"""
    is_valid, message, details = validate_format(BP_SAMPLE, 'BANQUE_POPULAIRE')
    assert is_valid, f"BP should be valid. Message: {message}"
    print("✅ Test BP validation passed")


def test_full_validation_lcl():
    """Test validation complète LCL"""
    result = validate_statement(LCL_SAMPLE)
    assert result['compatible'], "LCL should be compatible"
    assert result['bank'] == 'LCL'
    print("✅ Test full LCL validation passed")


def test_full_validation_unknown():
    """Test validation complète unknown"""
    result = validate_statement(UNKNOWN_SAMPLE)
    assert not result['compatible'], "Unknown bank should not be compatible"
    assert result['bank'] == 'UNKNOWN'
    print("✅ Test full unknown validation passed")


def run_all_tests():
    """Lance tous les tests"""
    print("\n" + "="*60)
    print("RUNNING BANK DETECTOR TESTS")
    print("="*60 + "\n")

    try:
        test_detect_lcl()
        test_detect_ca()
        test_detect_bp()
        test_detect_unknown()
        test_validate_lcl()
        test_validate_ca()
        test_validate_bp()
        test_full_validation_lcl()
        test_full_validation_unknown()

        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED!")
        print("="*60)
        return True
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return False


if __name__ == "__main__":
    run_all_tests()
