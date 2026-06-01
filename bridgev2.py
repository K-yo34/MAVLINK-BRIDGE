import os
import hmac
import hashlib
import struct
import threading
import logging
import secrets
from collections import deque
from typing import Optional, Tuple

# Attempt to import official ASCON library
try:
    import ascon as ascon_lib
    HAS_ASCON = True
    logging.info("ASCON-128a library loaded successfully")
except ImportError:
    HAS_ASCON = False
    logging.warning("ASCON library not found. Install with: pip install ascon")

class CryptoBridge:
    """
    ASCON-128a AEAD with explicit key versioning, sequence windows, and proper key separation.
    
    Packet Format:
    [KEY_ID(4) | SEQ(8) | NONCE(16) | CIPHERTEXT_LEN(4) | CIPHERTEXT(var) | ASCON_TAG(16)]
    
    Design decisions:
    - No HMAC wrapper: ASCON-128a provides 128-bit auth already. Adding HMAC is redundant and adds complexity.
    - Explicit key IDs instead of implicit rotation counters
    - 64-bit sequence numbers with sliding window for replay detection
    - Separate keys derived via HKDF-SHA256
    """
    
    KEY_LEN = 16          # ASCON-128a uses 128-bit keys
    NONCE_LEN = 16        # ASCON-128a uses 128-bit nonces
    TAG_LEN = 16          # ASCON-128a tag
    KEY_ID_LEN = 4
    SEQ_LEN = 8
    CT_LEN_FIELD = 4
    HEADER_LEN = KEY_ID_LEN + SEQ_LEN + NONCE_LEN + CT_LEN_FIELD  # 32 bytes
    
    # Replay window: accept packets within this range ahead of last seen
    WINDOW_SIZE = 64
    MAX_KEY_LIFETIME = 100000  # Max packets per key before mandatory rotation
    
    def __init__(self, master_secret: bytes):
        """
        Initialize with a master secret (32+ bytes recommended).
        Derives initial key and sets up state.
        """
        if len(master_secret) < 32:
            raise ValueError("Master secret must be at least 32 bytes")
            
        self._master_secret = master_secret
        self._lock = threading.RLock()
        self._key_id = 0
        self._key = self._derive_key(self._key_id)
        self._seq_tx = 0                    # Next sequence to transmit
        self._seq_rx = 0                    # Highest accepted sequence
        self._window = deque(maxlen=self.WINDOW_SIZE)  # Recent seen seqs
        self._msg_count = 0
        
    def _derive_key(self, key_id: int) -> bytes:
        """HKDF-like derivation: key = HMAC-SHA256(master, key_id || 'ascon-key')[:16]"""
        context = struct.pack('>I', key_id) + b'ascon-key'
        return hmac.new(self._master_secret, context, hashlib.sha256).digest()[:self.KEY_LEN]
    
    def _derive_next_key(self) -> Tuple[int, bytes]:
        """Generate next key ID and derived key."""
        next_id = (self._key_id + 1) & 0xFFFFFFFF
        return next_id, self._derive_key(next_id)
    
    def rotate_key(self) -> int:
        """Explicit key rotation. Returns new key ID."""
        with self._lock:
            self._key_id, self._key = self._derive_next_key()
            self._msg_count = 0
            # Note: seq_tx continues monotonically; key_id change signals rotation to peer
            logging.info(f"Key rotated to ID {self._key_id}")
            return self._key_id

    def encrypt(self, payload: bytes) -> bytes:
        """Encrypt payload with current key. Auto-rotate if key lifetime exceeded."""
        if not HAS_ASCON:
            raise RuntimeError("ASCON library required. Install: pip install ascon")
            
        if not isinstance(payload, bytes):
            raise TypeError("Payload must be bytes")
        
        with self._lock:
            # Auto-rotate on key lifetime
            if self._msg_count >= self.MAX_KEY_LIFETIME:
                self._key_id, self._key = self._derive_next_key()
                self._msg_count = 0
                logging.info(f"Auto-rotated to key ID {self._key_id}")
            
            key_id = self._key_id
            seq = self._seq_tx
            key = self._key
            
            self._seq_tx += 1
            self._msg_count += 1
        
        # Build nonce: first 8 bytes = key_id, last 8 bytes = random
        # This ensures nonce uniqueness even across key rotations
        nonce = struct.pack('>I', key_id) + os.urandom(self.NONCE_LEN - self.KEY_ID_LEN)
        
        # AAD includes key_id and seq for binding
        aad = struct.pack('>IQ', key_id, seq)
        
        # ASCON-128a AEAD
        ciphertext = ascon_lib.encrypt(key, nonce, payload, aad)
        
        # ciphertext format from ascon lib: encrypted_data || tag
        ct_body = ciphertext[:-self.TAG_LEN]
        tag = ciphertext[-self.TAG_LEN:]
        
        # Packet: [key_id | seq | nonce | ct_len | ciphertext | tag]
        packet = (
            struct.pack('>I', key_id) +
            struct.pack('>Q', seq) +
            nonce +
            struct.pack('>I', len(ct_body)) +
            ct_body +
            tag
        )
        
        return packet

    def decrypt(self, packet: bytes) -> Optional[bytes]:
        """
        Decrypt and verify packet. Returns plaintext or None if invalid.
        
        Security checks in order:
        1. Length validation
        2. Parse fields
        3. Key ID lookup (supports old keys briefly for transition)
        4. Sequence window check (anti-replay)
        5. ASCON AEAD verification (constant-time)
        """
        if not HAS_ASCON:
            raise RuntimeError("ASCON library required")
            
        # 1. Minimum length check
        min_len = self.HEADER_LEN + self.TAG_LEN
        if len(packet) < min_len:
            logging.debug("Packet too short")
            return None
        
        # 2. Parse header
        try:
            key_id = struct.unpack('>I', packet[:4])[0]
            seq = struct.unpack('>Q', packet[4:12])[0]
            nonce = packet[12:28]
            ct_len = struct.unpack('>I', packet[28:32])[0]
            
            expected_len = self.HEADER_LEN + ct_len + self.TAG_LEN
            if len(packet) != expected_len:
                logging.debug(f"Length mismatch: expected {expected_len}, got {len(packet)}")
                return None
                
            ct_body = packet[32:32+ct_len]
            tag = packet[32+ct_len:]
            
        except struct.error:
            logging.debug("Packet parsing failed")
            return None
        
        # 3. Key lookup
        with self._lock:
            if key_id == self._key_id:
                key = self._key
            elif key_id == (self._key_id - 1) & 0xFFFFFFFF:
                # Allow previous key for one window to handle transition
                key = self._derive_key(key_id)
            else:
                logging.warning(f"Unknown key ID: {key_id}")
                return None
            
            # 4. Replay detection with sliding window
            # Accept if: seq > seq_rx OR seq in window (for out-of-order within window)
            if seq <= self._seq_rx - self.WINDOW_SIZE:
                logging.warning(f"Replay detected: seq {seq} outside window")
                return None
            
            if seq in self._window:
                logging.warning(f"Replay detected: seq {seq} already seen")
                return None
            
            # Record sequence before verification (to prevent race conditions)
            # If verification fails, we still record it (DoS tradeoff: prefer no replays)
            if seq > self._seq_rx:
                self._seq_rx = seq
            self._window.append(seq)
        
        # 5. Reconstruct and verify
        aad = struct.pack('>IQ', key_id, seq)
        ciphertext = ct_body + tag
        
        try:
            plaintext = ascon_lib.decrypt(key, nonce, ciphertext, aad)
            return plaintext
        except Exception as e:
            logging.warning(f"ASCON decryption failed: {e}")
            return None