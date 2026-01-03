"""ML-KEM quantum-resistant key exchange.

This module provides post-quantum key exchange using ML-KEM-768 (formerly Kyber768).
The implementation uses the kyber-py library which provides a FIPS 203 compliant
implementation of the ML-KEM algorithm.
"""

from __future__ import annotations

import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

# Try to import from kyber-py library (FIPS 203 ML-KEM implementation)
# The library structure changed in version 1.0.0+
_KYBER_IMPL = None

try:
    # New API (kyber-py >= 1.0.0) - FIPS 203 ML-KEM
    from kyber_py.ml_kem import ML_KEM_768

    _KYBER_IMPL = ML_KEM_768
    logger.info("Using kyber-py ML-KEM-768 (FIPS 203) implementation")
except ImportError:
    try:
        # Legacy API (kyber-py < 1.0.0)
        from kyber_py.kyber768 import Kyber768

        _KYBER_IMPL = Kyber768
        logger.info("Using kyber-py Kyber768 (legacy) implementation")
    except ImportError as e:
        raise ImportError(
            "CRITICAL SECURITY ERROR: kyber-py library is REQUIRED for ML-KEM-768 implementation.\n"
            "This application CANNOT run securely without this dependency.\n"
            "Install with: pip install kyber-py>=0.1.0\n"
            "No fallback implementation exists - this is intentional for security."
        ) from e


class KyberWrapper:
    """Wrapper to provide a consistent API across different kyber-py versions."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate a new ML-KEM-768 key pair.

        Returns:
            Tuple of (public_key, private_key) as bytes
        """
        return _KYBER_IMPL.keygen()

    @staticmethod
    def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a shared secret for the given public key.

        Args:
            pk: The recipient's public key

        Returns:
            Tuple of (ciphertext, shared_secret)
        """
        # New API returns (shared_secret, ciphertext), legacy returns same
        result = _KYBER_IMPL.encaps(pk)
        # Both old and new API: (shared_key, ciphertext)
        shared_key, ciphertext = result
        return ciphertext, shared_key

    @staticmethod
    def decapsulate(c: bytes, sk: bytes) -> bytes:
        """Decapsulate a shared secret from ciphertext using private key.

        Args:
            c: The ciphertext from encapsulation
            sk: The private key

        Returns:
            The shared secret as bytes
        """
        return _KYBER_IMPL.decaps(sk, c)


KyberImpl = KyberWrapper


class MLKEMKeyExchange:
    """
    Post-quantum key exchange using a standard and secure ML-KEM-768 implementation.
    This class is a wrapper around the underlying Kyber implementation to align with the
    Sush protocol's architectural components.
    """

    # Standard ML-KEM-768 sizes
    PUBLIC_KEY_SIZE = 1184  # ML-KEM-768 public key size
    CIPHERTEXT_SIZE = 1088  # ML-KEM-768 ciphertext size
    SHARED_SECRET_SIZE = 32  # Kyber-768 produces a 32-byte shared secret

    def __init__(self):
        # Allow instantiation to work even if static methods are used directly elsewhere
        # The real logic is delegated to KyberImpl
        pass

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a new ML-KEM-768 public/private key pair."""
        try:
            return KyberImpl.generate_keypair()
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Create a shared secret and encapsulate it for the given public key."""
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size. Expected {self.PUBLIC_KEY_SIZE}, got {len(public_key)}"
            )

        try:
            return KyberImpl.encapsulate(public_key)
        except Exception as e:
            logger.error(f"Encapsulation failed: {e}")
            raise

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Extract the shared secret from a ciphertext using the private key."""
        if len(ciphertext) != self.CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid ciphertext size. Expected {self.CIPHERTEXT_SIZE}, got {len(ciphertext)}"
            )

        try:
            return KyberImpl.decapsulate(ciphertext, private_key)
        except Exception as e:
            logger.error(f"Decapsulation failed: {e}")
            raise

    def derive_keys(self, shared_secret: bytes, context: bytes = b"") -> dict[str, bytes]:
        """Derive symmetric keys from the shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=128,  # 32*4 bytes for 4 keys
            salt=None,
            info=b"Sush-ACS" + context,
        )

        key_material = hkdf.derive(shared_secret)

        return {
            "aes_key": key_material[:32],
            "chacha20_key": key_material[32:64],
            "hmac_key": key_material[64:96],
            "nonce": key_material[96:128],
        }

    def derive_symmetric_keys(self, shared_secret: bytes, context: bytes = b"") -> dict[str, bytes]:
        """
        Derive symmetric keys from shared secret with context.

        Alias for derive_keys method for compatibility.
        """
        return self.derive_keys(shared_secret, context)

    def get_parameters(self) -> dict[str, int]:
        """
        Return static parameter information about the underlying ML-KEM suite.

        The value is kept in a dict so callers can introspect capabilities
        without depending on the concrete implementation in use.
        """
        return {
            "public_key_size": self.PUBLIC_KEY_SIZE,
            "ciphertext_size": self.CIPHERTEXT_SIZE,
            "shared_secret_size": self.SHARED_SECRET_SIZE,
            "variant": "ML-KEM-768",
        }
