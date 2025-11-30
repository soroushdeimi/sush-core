"""ML-KEM quantum-resistant key exchange."""

import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

try:
    from kyber_py.kyber768 import Kyber768

    # Create a wrapper class to match expected interface
    class KyberWrapper:
        @staticmethod
        def generate_keypair():
            return Kyber768.keygen()

        @staticmethod
        def encapsulate(pk):
            return Kyber768.encaps(pk)

        @staticmethod
        def decapsulate(c, sk):
            return Kyber768.decaps(c, sk)

    KyberImpl = KyberWrapper
    logger.info("Using external kyber-py implementation")
except (ImportError, AttributeError):
    # Fallback to internal implementation
    try:
        from .kyber_impl import Kyber768

        KyberImpl = Kyber768
        logger.info("Using internal pure-python Kyber-768 implementation")
    except ImportError:
        # This should not happen if kyber_impl.py exists
        raise ImportError("Critical: No ML-KEM implementation found (external or internal)") from None


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
            # Try generate_keypair first (our internal impl)
            if hasattr(KyberImpl, "generate_keypair"):
                return KyberImpl.generate_keypair()
            # Fallback to keygen (kyber-py style)
            elif hasattr(KyberImpl, "keygen"):
                return KyberImpl.keygen()
            else:
                raise NotImplementedError("Unknown Kyber interface")
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
            # Try enc first (our internal impl matches this style usually or enc)
            if hasattr(KyberImpl, "enc"):
                return KyberImpl.enc(public_key)
            elif hasattr(KyberImpl, "encapsulate"):
                return KyberImpl.encapsulate(public_key)
            # Fallback to encaps (kyber-py style)
            elif hasattr(KyberImpl, "encaps"):
                return KyberImpl.encaps(public_key)
            else:
                raise NotImplementedError("Unknown Kyber interface")
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
            if hasattr(KyberImpl, "dec"):
                return KyberImpl.dec(ciphertext, private_key)
            elif hasattr(KyberImpl, "decapsulate"):
                return KyberImpl.decapsulate(ciphertext, private_key)
            elif hasattr(KyberImpl, "decaps"):
                return KyberImpl.decaps(ciphertext, private_key)
            else:
                raise NotImplementedError("Unknown Kyber interface")
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
