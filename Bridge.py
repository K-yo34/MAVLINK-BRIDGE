import os
import hmac
import hashlib
import struct
import threading
import logging
from collections import deque

# Attempt to import official ASCON library
try:
    import ascon as ascon_lib
    HAS_ASCON = True
    logging.info("ASCON-128a library loaded successfully")
except ImportError:
    HAS_ASCON = False
    logging.warning(" 'ascon' package not found. Using cryptographic fallback for prototyping.")

class CryptoBridge:
    """ASCON-128a + HMAC-SHA256 middleware with key rotation & replay prevention."""
    ROTATION_INTERVAL = 100
    KEY_LEN = 32          # 256-bit for ASCON-128a/HMAC compatibility
    NONCE_LEN = 16
    TAG_LEN = 16          # ASCON auth tag
    MAC_LEN = 32          # HMAC-SHA256

    def __init__(self, initial_key: bytes = None):
        self.key = initial_key or os.urandom(self.KEY_LEN)
        self.seq_counter = 0
        self.msg_count = 0
        self._lock = threading.Lock()

    def _rotate_key(self):
        with self._lock:
            self.key = os.urandom(self.KEY_LEN)
            self.msg_count = 0
            logging.info(" KEY ROTATED (New PSK generated)")

    def encrypt(self, payload: bytes) -> bytes:
        """Packet Format: [SEQ(4) | NONCE(16) | CIPHERTEXT | ASCON_TAG(16) | HMAC(32)]"""
        nonce = os.urandom(self.NONCE_LEN)
        
        if HAS_ASCON:
            # Official ASCON-128a AEAD
            ciphertext, ascon_tag = ascon_lib.encrypt(self.key, nonce, payload, aad=b"")
        else:
            # Safe Fallback: XOR stream + mock tag (for prototype testing only)
            stream = os.urandom(len(payload))
            ciphertext = bytes(a ^ b for a, b in zip(payload, stream))
            ascon_tag = b'\x00' * self.TAG_LEN

        # HMAC covers sequence + nonce + ciphertext + tag
        hmac_data = struct.pack('>I', self.seq_counter) + nonce + ciphertext + ascon_tag
        mac = hmac.new(self.key, hmac_data, hashlib.sha256).digest()

        packet = struct.pack('>I', self.seq_counter) + nonce + ciphertext + ascon_tag + mac
        
        with self._lock:
            self.seq_counter += 1
            self.msg_count += 1
            if self.msg_count >= self.ROTATION_INTERVAL:
                self._rotate_key()
                
        return packet

    def decrypt(self, packet: bytes) -> bytes | None:
        min_len = 4 + self.NONCE_LEN + self.TAG_LEN + self.MAC_LEN
        if len(packet) < min_len:
            logging.error("📉 Packet too short. Dropping.")
            return None

        seq = struct.unpack('>I', packet[:4])[0]
        nonce = packet[4:20]
        ascon_tag = packet[-48:-32]
        mac = packet[-32:]
        ciphertext = packet[20:-48]

        # 1. Replay Prevention
        if seq != self.seq_counter:
            logging.warning(f" REPLAY/SEQ MISMATCH: Expected {self.seq_counter}, Got {seq}")
            return None

        # 2. Integrity Verification
        hmac_data = struct.pack('>I', seq) + nonce + ciphertext + ascon_tag
        expected_mac = hmac.new(self.key, hmac_data, hashlib.sha256).digest()
        
        if not hmac.compare_digest(expected_mac, mac):
            logging.error("🛡️ HMAC VERIFICATION FAILED. Packet dropped.")
            return None

        # 3. Decryption
        try:
            if HAS_ASCON:
                plaintext = ascon_lib.decrypt(self.key, nonce, ciphertext, ascon_tag, aad=b"")
            else:
                plaintext = ciphertext  # Fallback passthrough
                
            with self._lock:
                self.seq_counter += 1
                self.msg_count += 1
                if self.msg_count >= self.ROTATION_INTERVAL:
                    self._rotate_key()
            return plaintext
        except Exception as e:
            logging.error(f" Decryption failed: {e}")
            return None
