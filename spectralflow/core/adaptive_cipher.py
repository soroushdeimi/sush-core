"""Adaptive cipher selection and dynamic encryption."""

import os
import time
from typing import List, Tuple
from enum import Enum, auto
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.backends import default_backend



class ThreatLevel(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


class NetworkCondition(Enum):
    HIGH_BANDWIDTH = auto()
    MEDIUM_BANDWIDTH = auto()
    LOW_BANDWIDTH = auto()
    UNSTABLE = auto()


@dataclass
class CipherProfile:
    name: str
    key_size: int
    iv_size: int
    performance_score: float
    security_score: float
    stealth_score: float


class AdaptiveCipherSuite:
    """Dynamic cipher selection based on network conditions."""
    
    def __init__(self):
        self.cipher_profiles = {
            'aes_gcm': CipherProfile('AES-256-GCM', 32, 12, 0.9, 0.8, 0.3),
            'chacha20': CipherProfile('ChaCha20-Poly1305', 32, 12, 0.8, 0.9, 0.7),
            'aes_ocb': CipherProfile('AES-256-OCB', 32, 15, 0.85, 0.8, 0.8)
        }
        self.active_cipher = 'aes_gcm'
        self.encryption_key = b''
        self.cipher_transitions = []
    
    def select_cipher(self, threat_level: ThreatLevel, network_condition: NetworkCondition) -> str:
        if threat_level == ThreatLevel.HIGH or threat_level == ThreatLevel.CRITICAL:
            if network_condition == NetworkCondition.HIGH_BANDWIDTH:
                return 'chacha20'
            else:
                return 'aes_ocb'
        else:
            return 'aes_gcm'
    
    def select_cipher_profile(self, threat_level: ThreatLevel, network_condition: NetworkCondition) -> CipherProfile:
        cipher_name = self.select_cipher(threat_level, network_condition)
        return self.cipher_profiles[cipher_name]
    
    def adapt_cipher(self, threat_level: ThreatLevel, network_condition: NetworkCondition):
        new_cipher = self.select_cipher(threat_level, network_condition)
        if new_cipher != self.active_cipher:
            self.active_cipher = new_cipher
            self.cipher_transitions.append((time.time(), new_cipher))
    
    def encrypt(self, data: bytes, additional_data: bytes = b"") -> Tuple[bytes, bytes, bytes]:
        if not self.encryption_key:
            raise ValueError("No encryption key set")
            
        profile = self.cipher_profiles[self.active_cipher]
        
        if self.active_cipher == 'aes_gcm':
            ciphertext, iv = self._encrypt_aes_gcm(data, self.encryption_key, profile)
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
            return ciphertext, iv, tag
        elif self.active_cipher == 'chacha20':
            ciphertext, nonce = self._encrypt_chacha20(data, self.encryption_key, profile)
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
            return ciphertext, nonce, tag
        elif self.active_cipher == 'aes_ocb':
            ciphertext, nonce = self._encrypt_aes_ocb(data, self.encryption_key, profile)
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
            return ciphertext, nonce, tag
        else:
            raise ValueError(f"Unknown cipher profile: {self.active_cipher}")
    
    def decrypt(self, ciphertext: bytes, iv: bytes, tag: bytes, additional_data: bytes = b"") -> bytes:
        if not self.encryption_key:
            raise ValueError("No encryption key set")
            
        profile = self.cipher_profiles[self.active_cipher]
        
        if self.active_cipher == 'aes_gcm':
            return self._decrypt_aes_gcm_with_tag(ciphertext, self.encryption_key, iv, tag, profile)
        elif self.active_cipher == 'chacha20':
            full_ciphertext = ciphertext + tag
            return self._decrypt_chacha20(full_ciphertext, self.encryption_key, iv, profile)
        elif self.active_cipher == 'aes_ocb':
            full_ciphertext = ciphertext + tag
            return self._decrypt_aes_ocb(full_ciphertext, self.encryption_key, iv, profile)
        else:
            raise ValueError(f"Unknown cipher profile: {self.active_cipher}")
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes, profile: CipherProfile) -> Tuple[bytes, bytes]:
        iv = os.urandom(profile.iv_size)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + encryptor.tag, iv
    
    def _decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, iv: bytes, profile: CipherProfile) -> bytes:
        tag = ciphertext[-16:]
        actual_ciphertext = ciphertext[:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(actual_ciphertext) + decryptor.finalize()

    def _decrypt_aes_gcm_with_tag(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes, profile: CipherProfile) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _encrypt_chacha20(self, data: bytes, key: bytes, profile: CipherProfile) -> Tuple[bytes, bytes]:
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, data, None)
        return ciphertext, nonce
    
    def _decrypt_chacha20(self, ciphertext: bytes, key: bytes, nonce: bytes, profile: CipherProfile) -> bytes:
        cipher = ChaCha20Poly1305(key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"ChaCha20-Poly1305 decryption failed: {e}")
    
    def _encrypt_aes_ocb(self, data: bytes, key: bytes, profile: CipherProfile) -> Tuple[bytes, bytes]:
        cipher = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, data, None)
        return ciphertext, nonce

    def _decrypt_aes_ocb(self, ciphertext: bytes, key: bytes, nonce: bytes, profile: CipherProfile) -> bytes:
        cipher = AESGCM(key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"AES-GCM decryption failed: {e}")
    
    def get_current_profile_info(self) -> dict:
        profile = self.cipher_profiles[self.active_cipher]
        return {
            'name': profile.name,
            'key_size': profile.key_size,
            'iv_size': profile.iv_size,
            'performance_score': profile.performance_score,
            'security_score': profile.security_score,
            'stealth_score': profile.stealth_score
        }
    
    def get_transition_history(self) -> List[Tuple[float, str]]:
        return self.cipher_transitions.copy()


def create_adaptive_cipher(threat_level: str = 'low', network_condition: str = 'high_bandwidth') -> AdaptiveCipherSuite:
    threat_map = {
        'low': ThreatLevel.LOW,
        'medium': ThreatLevel.MEDIUM,
        'high': ThreatLevel.HIGH,
        'critical': ThreatLevel.CRITICAL
    }
    
    network_map = {
        'high_bandwidth': NetworkCondition.HIGH_BANDWIDTH,
        'medium_bandwidth': NetworkCondition.MEDIUM_BANDWIDTH,
        'low_bandwidth': NetworkCondition.LOW_BANDWIDTH,
        'unstable': NetworkCondition.UNSTABLE
    }
    
    cipher_suite = AdaptiveCipherSuite()
    cipher_suite.adapt_cipher(
        threat_map.get(threat_level, ThreatLevel.LOW),
        network_map.get(network_condition, NetworkCondition.HIGH_BANDWIDTH)
    )
    
    return cipher_suite
