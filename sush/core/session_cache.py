"""
Session Cache for ML-KEM Session Resumption.

Reduces handshake overhead by caching session secrets and allowing
fast resumption of previous sessions.
"""

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass
class CachedSession:
    """Cached session data for resumption."""

    session_id: str
    shared_secret: bytes
    derived_keys: dict[str, bytes]
    peer_public_key_hash: bytes
    created_at: float
    last_used: float
    use_count: int = 0


class SessionCache:
    """
    LRU cache for session resumption.
    
    Caches ML-KEM shared secrets and derived keys to avoid
    expensive key exchange on session resumption.
    """

    def __init__(self, max_size: int = 100, ttl: float = 3600.0):
        """
        Initialize session cache.

        Args:
            max_size: Maximum number of cached sessions
            ttl: Time-to-live for cached sessions in seconds (default: 1 hour)
        """
        self.logger = logging.getLogger(__name__)
        self.max_size = max_size
        self.ttl = ttl
        self.cache: dict[str, CachedSession] = {}
        self.access_order: list[str] = []  # For LRU eviction

    def _hash_peer_key(self, peer_public_key: bytes) -> str:
        """Generate hash of peer public key for cache key."""
        return hashlib.sha256(peer_public_key).hexdigest()[:16]

    def store_session(
        self,
        session_id: str,
        shared_secret: bytes,
        derived_keys: dict[str, bytes],
        peer_public_key: bytes,
    ) -> None:
        """
        Store session data for future resumption.

        Args:
            session_id: Unique session identifier
            shared_secret: ML-KEM shared secret
            derived_keys: Derived symmetric keys
            peer_public_key: Peer's public key
        """
        cache_key = self._hash_peer_key(peer_public_key)
        now = time.time()

        # Evict expired or old entries if cache is full
        if len(self.cache) >= self.max_size:
            self._evict_oldest()

        cached = CachedSession(
            session_id=session_id,
            shared_secret=shared_secret,
            derived_keys=derived_keys,
            peer_public_key_hash=peer_public_key,
            created_at=now,
            last_used=now,
            use_count=0,
        )

        self.cache[cache_key] = cached
        self._update_access_order(cache_key)

        self.logger.debug(f"Cached session {session_id} for resumption")

    def get_session(
        self, peer_public_key: bytes
    ) -> Optional[tuple[bytes, dict[str, bytes]]]:
        """
        Retrieve cached session data.

        Args:
            peer_public_key: Peer's public key

        Returns:
            Tuple of (shared_secret, derived_keys) if found and valid, None otherwise
        """
        cache_key = self._hash_peer_key(peer_public_key)

        if cache_key not in self.cache:
            return None

        cached = self.cache[cache_key]
        now = time.time()

        # Check if session expired
        if now - cached.created_at > self.ttl:
            self.logger.debug(f"Session {cached.session_id} expired, removing from cache")
            del self.cache[cache_key]
            if cache_key in self.access_order:
                self.access_order.remove(cache_key)
            return None

        # Update access info
        cached.last_used = now
        cached.use_count += 1
        self._update_access_order(cache_key)

        self.logger.debug(
            f"Resumed session {cached.session_id} (use count: {cached.use_count})"
        )

        return (cached.shared_secret, cached.derived_keys)

    def _update_access_order(self, cache_key: str) -> None:
        """Update LRU access order."""
        if cache_key in self.access_order:
            self.access_order.remove(cache_key)
        self.access_order.append(cache_key)

    def _evict_oldest(self) -> None:
        """Evict least recently used session."""
        if not self.access_order:
            return

        oldest_key = self.access_order.pop(0)
        if oldest_key in self.cache:
            evicted = self.cache[oldest_key]
            del self.cache[oldest_key]
            self.logger.debug(f"Evicted session {evicted.session_id} from cache")

    def clear_expired(self) -> int:
        """
        Remove all expired sessions.

        Returns:
            Number of sessions removed
        """
        now = time.time()
        expired_keys = [
            key
            for key, cached in self.cache.items()
            if now - cached.created_at > self.ttl
        ]

        for key in expired_keys:
            del self.cache[key]
            if key in self.access_order:
                self.access_order.remove(key)

        if expired_keys:
            self.logger.debug(f"Cleared {len(expired_keys)} expired sessions")

        return len(expired_keys)

    def get_stats(self) -> dict[str, int]:
        """Get cache statistics."""
        now = time.time()
        active = sum(1 for c in self.cache.values() if now - c.created_at <= self.ttl)
        total_uses = sum(c.use_count for c in self.cache.values())

        return {
            "cached_sessions": len(self.cache),
            "active_sessions": active,
            "total_resumptions": total_uses,
            "max_size": self.max_size,
        }

