"""ML-KEM quantum-resistant key exchange."""

import logging

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

try:
    from kyber_py.kyber768 import Kyber768
except ImportError:
    # Fallback for different package structure
    try:
        import kyber_py

        Kyber768 = kyber_py.Kyber768
    except (ImportError, AttributeError):
        # Fail loud if dependency is missing rather than silently using insecure mock
        raise ImportError(
            "kyber-py is required for ML-KEM key exchange. "
            "Install it with: pip install kyber-py>=0.1.0\n"
            "Note: kyber-py is marked for educational use only. "
            "For production, consider using liboqs-python or pyca/cryptography once ML-KEM is fully supported."
        ) from None


class MLKEMKeyExchange:
    """
    Post-quantum key exchange using a standard and secure ML-KEM-768 implementation.
    This class is a wrapper around the 'kyber-py' library to align with the
    SpectralFlow protocol's architectural components.
    """

    # Standard ML-KEM-768 sizes
    PUBLIC_KEY_SIZE = 1184  # ML-KEM-768 public key size
    CIPHERTEXT_SIZE = 1088  # ML-KEM-768 ciphertext size
    SHARED_SECRET_SIZE = 32  # Kyber-768 produces a 32-byte shared secret

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a new ML-KEM-768 public/private key pair."""
        public_key, private_key = Kyber768.keygen()
        return public_key, private_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Create a shared secret and encapsulate it for the given public key."""
        if len(public_key) != self.PUBLIC_KEY_SIZE:
            raise ValueError(
                f"Invalid public key size. Expected {self.PUBLIC_KEY_SIZE}, got {len(public_key)}"
            )

        ciphertext, shared_secret = Kyber768.encaps(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Extract the shared secret from a ciphertext using the private key."""
        if len(ciphertext) != self.CIPHERTEXT_SIZE:
            raise ValueError(
                f"Invalid ciphertext size. Expected {self.CIPHERTEXT_SIZE}, got {len(ciphertext)}"
            )

        shared_secret = Kyber768.decaps(ciphertext, private_key)
        return shared_secret

    def derive_keys(self, shared_secret: bytes, context: bytes = b"") -> dict[str, bytes]:
        """Derive symmetric keys from the shared secret using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=128,  # 32*4 bytes for 4 keys
            salt=None,
            info=b"SpectralFlow-ACS" + context,
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
