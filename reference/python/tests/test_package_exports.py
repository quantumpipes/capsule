"""
Smoke tests: public qp-capsule exports for CPS protocol features (FR-002, FR-003).
"""

import qp_capsule


def test_fr002_validation_exports():
    assert hasattr(qp_capsule, "validate_capsule_dict")
    assert hasattr(qp_capsule, "validate_capsule")
    assert hasattr(qp_capsule, "CapsuleValidationResult")
    assert callable(qp_capsule.validate_capsule_dict)
    assert callable(qp_capsule.validate_capsule)


def test_fr003_seal_verify_exports():
    assert hasattr(qp_capsule, "SealVerifyCode")
    assert hasattr(qp_capsule, "SealVerificationResult")
    assert hasattr(qp_capsule.Seal, "verify_detailed")
    assert hasattr(qp_capsule.Seal, "verify_with_key_detailed")
