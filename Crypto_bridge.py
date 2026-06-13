import os
import sys
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_VENV_SITE = os.path.join(os.path.dirname(_HERE), 'capstone 2', 'env', 'Lib', 'site-packages')
if os.path.isdir(_VENV_SITE) and _VENV_SITE not in sys.path:
    sys.path.insert(0, _VENV_SITE)
for _ver in ['312', '311', '310', '313']:
    _sp = os.path.join(f'C:/Python{_ver}', 'Lib', 'site-packages')
    if os.path.isdir(_sp) and _sp not in sys.path:
        sys.path.insert(0, _sp)

import hmac
import hashlib
import struct
import threading
import logging
from collections import deque
from typing import Optional, Tuple

try:
    import ascon as ascon_lib
    HAS_ASCON = True
except ImportError:
    HAS_ASCON = False
    logging.warning("ASCON library not found. Install: pip install ascon")

class CryptoBridge:
    KEY_LEN = 16
    NONCE_LEN = 16
    TAG_LEN = 16
    KEY_ID_LEN = 4
    SEQ_LEN = 8
    CT_LEN_FIELD = 4
    HEADER_LEN = KEY_ID_LEN + SEQ_LEN + NONCE_LEN + CT_LEN_FIELD
    WINDOW_SIZE = 64
    MAX_KEY_LIFETIME = 100

    def __init__(self, master_secret: bytes):
        if len(master_secret) < 32:
            raise ValueError("Master secret must be at least 32 bytes")
        self._master_secret = master_secret
        self._lock = threading.RLock()
        self._key_id = 0
        self._key = self._derive_key(self._key_id)
        self._seq_tx = 0
        self._seq_rx = 0
        self._window = deque(maxlen=self.WINDOW_SIZE)
        self._msg_count = 0

    @property
    def key_id(self) -> int:
        return self._key_id

    def _derive_key(self, key_id: int) -> bytes:
        context = struct.pack('>I', key_id) + b'ascon-key'
        return hmac.new(self._master_secret, context, hashlib.sha256).digest()[:self.KEY_LEN]

    def _derive_next_key(self) -> Tuple[int, bytes]:
        next_id = (self._key_id + 1) & 0xFFFFFFFF
        return next_id, self._derive_key(next_id)

    def rotate_key(self) -> int:
        with self._lock:
            self._key_id, self._key = self._derive_next_key()
            self._msg_count = 0
            return self._key_id

    def encrypt(self, payload: bytes) -> bytes:
        if not HAS_ASCON:
            raise RuntimeError("ASCON library required")
        if not isinstance(payload, bytes):
            raise TypeError("Payload must be bytes")

        with self._lock:
            if self._msg_count >= self.MAX_KEY_LIFETIME:
                self._key_id, self._key = self._derive_next_key()
                self._msg_count = 0
            key_id = self._key_id
            seq = self._seq_tx
            key = self._key
            self._seq_tx += 1
            self._msg_count += 1

        nonce = struct.pack('>I', key_id) + os.urandom(self.NONCE_LEN - self.KEY_ID_LEN)
        aad = struct.pack('>IQ', key_id, seq)
        combined = ascon_lib.encrypt(key, nonce, aad, payload)
        ct_body = combined[:-self.TAG_LEN]
        tag = combined[-self.TAG_LEN:]

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
        if not HAS_ASCON:
            raise RuntimeError("ASCON library required")

        min_len = self.HEADER_LEN + self.TAG_LEN
        if len(packet) < min_len:
            return None

        try:
            key_id = struct.unpack('>I', packet[:4])[0]
            seq = struct.unpack('>Q', packet[4:12])[0]
            nonce = packet[12:28]
            ct_len = struct.unpack('>I', packet[28:32])[0]
            expected_len = self.HEADER_LEN + ct_len + self.TAG_LEN
            if len(packet) != expected_len:
                return None
            ct_body = packet[32:32+ct_len]
            tag = packet[32+ct_len:]
        except struct.error:
            return None

        with self._lock:
            if key_id == self._key_id:
                key = self._key
                advance_key = False
            elif key_id == (self._key_id - 1) & 0xFFFFFFFF:
                key = self._derive_key(key_id)
                advance_key = False
            elif key_id == (self._key_id + 1) & 0xFFFFFFFF:
                key = self._derive_key(key_id)
                advance_key = True
            else:
                return None

            if seq <= self._seq_rx - self.WINDOW_SIZE:
                return None
            if seq in self._window:
                return None

        aad = struct.pack('>IQ', key_id, seq)
        combined = ct_body + tag

        try:
            plaintext = ascon_lib.decrypt(key, nonce, aad, combined)
            if plaintext is None:
                return None
        except Exception:
            return None

        with self._lock:
            if seq <= self._seq_rx - self.WINDOW_SIZE or seq in self._window:
                return None
            if seq > self._seq_rx:
                self._seq_rx = seq
            self._window.append(seq)
            if advance_key and key_id == (self._key_id + 1) & 0xFFFFFFFF:
                self._key_id = key_id
                self._key = key

        return plaintext
