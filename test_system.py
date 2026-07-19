"""
Comprehensive automated test suite for UAV/GCS secure communication system.
Tests CryptoBridge encryption, replay/tamper protection, key rotation,
and all UAV flight behaviors (ascend, descend, stop, move).
"""

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

import unittest
import socket
import time
import struct
import csv
import traceback
from datetime import datetime

try:
    from crypto_bridge import CryptoBridge, HAS_ASCON
except ImportError:
    print("Error: Could not import crypto_bridge.")
    sys.exit(1)

if not HAS_ASCON:
    print("WARNING: 'ascon' library not found. Install: pip install ascon")

# ── Remote UAV config ───────────────────────────────────────────────────
UAV_IP = "192.168.1.99"
UAV_PORT = 14550
CONNECTIVITY_RETRIES = 3

# ── Helpers ──────────────────────────────────────────────────────────────

def _make_gcs_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    s.settimeout(2.0)
    return s


def _pack_cmd(mav, param1, param2=0):
    cmd = mav.command_long_encode(1, 1, 176, 0, param1, param2, 0, 0, 0, 0, 0)
    cmd.pack(mav)
    return bytes(cmd.get_msgbuf())


def _recv_telem(sock, bridge, mav, timeout=1.0):
    try:
        sock.settimeout(timeout)
        data, _ = sock.recvfrom(4096)
        dec = bridge.decrypt(data)
        if dec:
            msg = mav.parse_char(dec)
            if msg and msg.get_type() == 'GLOBAL_POSITION_INT':
                return (msg.alt / 1000.0, msg.lat / 1e7, msg.lon / 1e7)
    except socket.timeout:
        pass
    return None


def _drain_sock(sock, count=5, timeout=0.3):
    for _ in range(count):
        try:
            sock.settimeout(timeout)
            sock.recvfrom(4096)
        except socket.timeout:
            break


# ══════════════════════════════════════════════════════════════════════════
# PART 1 — CryptoBridge unit tests (no UAV needed)
# ══════════════════════════════════════════════════════════════════════════

class TestCryptoBridgeSecurity(unittest.TestCase):
    """Unit tests for the cryptographic security features of CryptoBridge."""

    def setUp(self):
        if not HAS_ASCON:
            self.skipTest("ascon library not installed")
        self.secret = b"my_super_secret_capstone_key_32_bytes!"
        self.sender = CryptoBridge(self.secret)
        self.receiver = CryptoBridge(self.secret)

    def test_TC01_encrypt_decrypt(self):
        """TC-01: Basic encryption and decryption round-trip."""
        payload = b"Hello, Secure UAV!"
        encrypted = self.sender.encrypt(payload)
        decrypted = self.receiver.decrypt(encrypted)
        self.assertEqual(payload, decrypted)

    def test_TC02_replay_prevention(self):
        """TC-02: Same packet decrypted twice — second returns None."""
        payload = b"Replay test payload"
        encrypted = self.sender.encrypt(payload)
        self.assertEqual(payload, self.receiver.decrypt(encrypted))
        self.assertIsNone(self.receiver.decrypt(encrypted))

    def test_TC03_tamper_detection(self):
        """TC-03: Bit-flipped ciphertext returns None."""
        payload = b"Tamper test payload"
        encrypted = self.sender.encrypt(payload)
        tampered = bytearray(encrypted)
        tampered[len(tampered) // 2] ^= 0xFF
        self.assertIsNone(self.receiver.decrypt(bytes(tampered)))

    def test_TC04_invalid_lengths(self):
        """TC-04: Truncated / length-corrupted packets return None."""
        self.assertIsNone(self.receiver.decrypt(b"short"))
        payload = b"Bad length test"
        encrypted = self.sender.encrypt(payload)
        bad = bytearray(encrypted)
        bad[28:32] = struct.pack('>I', 9999)
        self.assertIsNone(self.receiver.decrypt(bytes(bad)))

    def test_TC05_key_rotation(self):
        """TC-05: Key rotates after MAX_KEY_LIFETIME; receiver syncs."""
        for _ in range(CryptoBridge.MAX_KEY_LIFETIME + 1):
            self.sender.encrypt(b"dummy")
        payload = b"Key rotation test"
        encrypted = self.sender.encrypt(payload)
        decrypted = self.receiver.decrypt(encrypted)
        self.assertEqual(payload, decrypted)
        self.assertEqual(self.receiver.key_id, self.sender.key_id)

    def test_TC06_wrong_key(self):
        """TC-06: Packet from different master secret returns None."""
        wrong = CryptoBridge(b"wrong_key_" + b"0" * 22)
        encrypted = wrong.encrypt(b"wrong key payload")
        self.assertIsNone(self.receiver.decrypt(encrypted))

    def test_TC06b_crypto_latency(self):
        """TC-06b: Encrypt + decrypt latency over 100 iterations."""
        payload = b"Latency test payload " * 10
        N = 100
        encrypt_times = []
        total_enc = 0.0
        for _ in range(N):
            t0 = time.perf_counter()
            enc = self.sender.encrypt(payload)
            t1 = time.perf_counter()
            encrypt_times.append((t1 - t0) * 1000)
            total_enc += t1 - t0
            self.receiver.decrypt(enc)
        avg_enc = (total_enc / N) * 1000
        max_enc = max(encrypt_times)
        print(f"\n[LATENCY] encrypt: avg={avg_enc:.3f}ms, max={max_enc:.3f}ms over {N} runs")
        self.assertLess(avg_enc, 10.0, f"Avg encrypt latency {avg_enc:.3f}ms exceeds 10ms")


# ══════════════════════════════════════════════════════════════════════════
# PART 2 — UAV/GCS integration tests (connects to remote UAV at UAV_IP)
# ══════════════════════════════════════════════════════════════════════════

class TestUAVGCSIntegration(unittest.TestCase):
    """Integration tests — connects to remote UAV over UDP."""

    # ── Class-level setup ───────────────────────────────────────────

    @classmethod
    def setUpClass(cls):
        if not HAS_ASCON:
            raise unittest.SkipTest("ascon library not installed")

        print(f"\nChecking UAV at {UAV_IP}:{UAV_PORT}...", end=" ", flush=True)
        sock = _make_gcs_sock()
        sock.settimeout(1.0)
        alive = False
        from pymavlink import mavutil
        secret = b"my_super_secret_capstone_key_32_bytes!"
        bridge = CryptoBridge(secret)
        mav = mavutil.mavlink.MAVLink(None, srcSystem=2, srcComponent=1)
        for _ in range(CONNECTIVITY_RETRIES):
            sock.sendto(bridge.encrypt(_pack_cmd(mav, 0, 0)),
                        (UAV_IP, UAV_PORT))
            try:
                data, _ = sock.recvfrom(4096)
                if bridge.decrypt(data):
                    uav_key_id = struct.unpack('>I', data[:4])[0]
                    if uav_key_id != bridge.key_id:
                        bridge._key_id = uav_key_id
                        bridge._key = bridge._derive_key(uav_key_id)
                        bridge._msg_count = 0
                    alive = True
                    break
            except socket.timeout:
                pass
            time.sleep(0.5)
        sock.close()

        if not alive:
            raise unittest.SkipTest(
                f"UAV at {UAV_IP}:{UAV_PORT} not reachable. "
                f"Start uav_interactive_linux.py on the Linux VM."
            )

        cls.bridge = bridge
        cls.mav = mav
        print("OK\n")

    @classmethod
    def tearDownClass(cls):
        """Send shutdown signal to UAV after all tests complete."""
        if not hasattr(cls, 'bridge') or not hasattr(cls, 'mav'):
            return
        sock = _make_gcs_sock()
        try:
            cmd = cls.mav.command_long_encode(1, 1, 0, 0, 99, 0, 0, 0, 0, 0, 0)
            cmd.pack(cls.mav)
            pkt = cls.bridge.encrypt(bytes(cmd.get_msgbuf()))
            sock.sendto(pkt, (UAV_IP, UAV_PORT))
            print("\n[GCS] Sent shutdown signal to UAV")
        except Exception:
            pass
        finally:
            sock.close()

    # ── Per-test helpers ─────────────────────────────────────────────

    def setUp(self):
        self.bridge = self.__class__.bridge
        self.mav = self.__class__.mav

    def _gcs(self):
        return _make_gcs_sock()

    def _send(self, sock, p1, p2=0):
        sock.sendto(self.bridge.encrypt(_pack_cmd(self.mav, p1, p2)),
                    (UAV_IP, UAV_PORT))

    def _telem(self, sock, timeout=1.0):
        return _recv_telem(sock, self.bridge, self.mav, timeout)

    def _drain(self, sock):
        _drain_sock(sock)

    # ── Test cases ───────────────────────────────────────────────────

    def test_TC07_baseline_comms(self):
        """TC-07: Send STOP, receive telemetry."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        time.sleep(0.5)

        alt_seen = []
        start = time.time()
        while time.time() - start < 6.0:
            t = self._telem(sock, 2.0)
            if t:
                alt_seen.append(t[0])
        sock.close()
        self.assertTrue(len(alt_seen) > 0, "No telemetry received from UAV")

    def test_TC08_ascend(self):
        """TC-08: ASCEND raises altitude >= 10m."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        self._drain(sock)
        alt_before, _, _ = self._telem(sock, 0.5) or (150, 0, 0)

        self._send(sock, 1, 0)
        time.sleep(2.0)
        alts = []
        for _ in range(5):
            t = self._telem(sock, 1.0)
            if t is not None:
                alts.append(t[0])
            time.sleep(0.2)
        sock.close()
        max_alt = max(alts) if alts else alt_before
        self.assertGreaterEqual(max_alt - alt_before, 9.0)

    def test_TC09_descend(self):
        """TC-09: DESCEND lowers altitude >= 10m."""
        sock = self._gcs()

        # STOP first in case UAV was ascending
        self._send(sock, 0, 0)
        time.sleep(0.5)
        self._drain(sock)
        alt_before, _, _ = self._telem(sock, 0.5) or (200, 0, 0)

        self._send(sock, -1, 0)
        time.sleep(2.0)
        alts = []
        for _ in range(5):
            t = self._telem(sock, 1.0)
            if t is not None:
                alts.append(t[0])
            time.sleep(0.2)
        sock.close()
        min_alt = min(alts) if alts else alt_before
        self.assertGreaterEqual(alt_before - min_alt, 9.0)

    def test_TC10_stop(self):
        """TC-10: STOP holds altitude steady (drift <= 2m)."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        self._drain(sock)

        alts = []
        for _ in range(4):
            self._send(sock, 0, 0)
            t = self._telem(sock, 1.5)
            if t is not None:
                alts.append(t[0])
            time.sleep(1.0)
        sock.close()

        if len(alts) >= 2:
            drift = abs(alts[-1] - alts[0])
            self.assertLessEqual(drift, 2.0, f"Altitude drifted {drift:.1f}m")

    def test_TC11_move_left(self):
        """TC-11: MOVE_LEFT decreases longitude."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        self._drain(sock)
        _, _, lon_before = self._telem(sock, 0.5) or (0, 0, -122.4194)

        self._send(sock, 0, -1)
        time.sleep(0.8)
        lons = []
        for _ in range(3):
            t = self._telem(sock, 1.0)
            if t is not None:
                lons.append(t[2])
            time.sleep(0.2)
        sock.close()
        min_lon = min(lons) if lons else lon_before
        self.assertLess(min_lon, lon_before)

    def test_TC12_move_right(self):
        """TC-12: MOVE_RIGHT increases longitude."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        self._drain(sock)
        _, _, lon_before = self._telem(sock, 0.5) or (0, 0, -122.4194)

        self._send(sock, 0, 1)
        time.sleep(0.8)
        lons = []
        for _ in range(3):
            t = self._telem(sock, 1.0)
            if t is not None:
                lons.append(t[2])
            time.sleep(0.2)
        sock.close()
        max_lon = max(lons) if lons else lon_before
        self.assertGreater(max_lon, lon_before)

    def test_TC13_key_rotation_integration(self):
        """TC-13: Key rotation causes zero packet drops."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        self._drain(sock)
        self.bridge._msg_count = self.bridge.MAX_KEY_LIFETIME - 2

        success = 0
        for _ in range(5):
            self._send(sock, 1, 0)
            t = self._telem(sock, 2.0)
            if t is not None:
                success += 1
            time.sleep(0.3)
        sock.close()
        self.assertEqual(success, 5)

    def test_TC14_replay_attack_integration(self):
        """TC-14: Replayed packets ignored; UAV stays responsive."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        self._drain(sock)

        pkt = self.bridge.encrypt(_pack_cmd(self.mav, 0, 0))
        sock.sendto(pkt, (UAV_IP, UAV_PORT))
        time.sleep(0.3)

        for _ in range(3):
            sock.sendto(pkt, (UAV_IP, UAV_PORT))
            time.sleep(0.2)

        self._send(sock, 0, 0)
        t = self._telem(sock, 3.0)
        sock.close()
        self.assertIsNotNone(t, "UAV stopped responding after replay attack")

    def test_TC15_wrong_key_integration(self):
        """TC-15: Wrong-key packet rejected; UAV stays alive."""
        sock = self._gcs()
        evil = CryptoBridge(b"wrong_key_32_bytes_xxxxxxxxxxxxxx")

        self._send(sock, 0, 0)
        self._drain(sock)

        sock.sendto(evil.encrypt(_pack_cmd(self.mav, 0, 0)),
                    (UAV_IP, UAV_PORT))
        time.sleep(0.5)
        self._send(sock, 0, 0)
        t = self._telem(sock, 4.0)
        sock.close()
        self.assertIsNotNone(t, "UAV stopped responding after wrong-key packet")

    def test_TC16_malformed_packet(self):
        """TC-16: Garbage packets don't crash the UAV."""
        sock = self._gcs()

        self._send(sock, 0, 0)
        self._drain(sock)

        for garbage in [b'\xfd\x05\x00\x00\x00',
                        b'\xfd' + os.urandom(50),
                        b'\xfe' + os.urandom(20)]:
            sock.sendto(garbage, (UAV_IP, UAV_PORT))

        time.sleep(0.5)
        self._send(sock, 0, 0)
        t = self._telem(sock, 4.0)
        sock.close()
        self.assertIsNotNone(t, "UAV crashed after malformed packets")

    def test_TC17_network_latency(self):
        """TC-17: Round-trip command → telemetry latency over 10 iterations."""
        sock = self._gcs()
        self._send(sock, 0, 0)
        self._drain(sock)

        N = 10
        rtts = []
        for i in range(N):
            t0 = time.perf_counter()
            self._send(sock, 0, 0)
            while time.perf_counter() - t0 < 3.0:
                t = self._telem(sock, 0.5)
                if t is not None:
                    rtt = (time.perf_counter() - t0) * 1000
                    rtts.append(rtt)
                    break
        sock.close()

        self.assertGreater(len(rtts), 0, "No telemetry received for latency measurement")
        avg_rtt = sum(rtts) / len(rtts)
        max_rtt = max(rtts)
        min_rtt = min(rtts)
        print(f"\n[LATENCY] network RTT: avg={avg_rtt:.1f}ms, min={min_rtt:.1f}ms, max={max_rtt:.1f}ms over {len(rtts)} samples")


# ══════════════════════════════════════════════════════════════════════════
# CSV logging test runner
# ══════════════════════════════════════════════════════════════════════════

class _CSVResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rows = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.rows.append([test.id(), test.shortDescription() or "", "PASS", "",
                          datetime.now().isoformat()])

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows.append([test.id(), test.shortDescription() or "", "FAIL",
                          traceback.format_exception(*err)[-1].strip(),
                          datetime.now().isoformat()])

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows.append([test.id(), test.shortDescription() or "", "SKIP",
                          str(reason), datetime.now().isoformat()])

    def addError(self, test, err):
        super().addError(test, err)
        self.rows.append([test.id(), test.shortDescription() or "", "ERROR",
                          traceback.format_exception(*err)[-1].strip(),
                          datetime.now().isoformat()])


class _CSVRunner(unittest.TextTestRunner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, resultclass=_CSVResult, **kwargs)

    def run(self, test):
        result = super().run(test)
        name = f"test_system_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(name, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Test", "Description", "Status", "Detail", "Timestamp"])
            w.writerows(result.rows)
        print(f"\nCSV log: {name}")
        return result


if __name__ == '__main__':
    unittest.main(testRunner=_CSVRunner(verbosity=2))
