import socket
import threading
import time
import random
import psutil
from collections import deque
from queue import Queue
from crypto_bridge import CryptoBridge

import logging
logging.getLogger().setLevel(logging.CRITICAL)

def extract_mavlink_msgid(raw: bytes) -> str:
    if not raw or len(raw) < 6:
        return "Unknown"
    if raw[0] == 0xFD:
        msg_id = raw[7] | (raw[8] << 8) | (raw[9] << 16)
        return str(msg_id)
    if raw[0] == 0xFE:
        return str(raw[5])
    return "Unknown"

class SecureMAVLinkBridge:
    def __init__(self, app_port, rf_send_addr, rf_listen_port, master_secret, name="Bridge", csv_path=None):
        self.name = name
        self.app_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.app_sock.bind(("127.0.0.1", app_port))
        self.app_sock.settimeout(0.1)

        self.rf_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.rf_sock.bind(("127.0.0.1", rf_listen_port))
        self.rf_sock.settimeout(0.1)

        self.rf_send_addr = rf_send_addr
        self.crypto = CryptoBridge(master_secret)
        self.app_peer_addr = None
        self.running = False

        if csv_path is None:
            csv_path = f"mission_metrics_{name.lower().replace('-', '_')}.csv"
        self.csv_path = csv_path
        self.csv_file = open(self.csv_path, 'w', newline='')
        self.csv_file.write("Timestamp,Direction,Latency_ms,Msg_ID,Key_ID,CPU_pct,Status\n")
        self.csv_queue = Queue()
        threading.Thread(target=self._csv_writer_loop, daemon=True).start()

    def start(self):
        self.running = True
        threading.Thread(target=self._app_to_rf_loop, daemon=True).start()
        threading.Thread(target=self._rf_to_app_loop, daemon=True).start()
        print(f"   ✅ [{self.name}] Online | App Port: {self.app_sock.getsockname()[1]}, RF Listen: {self.rf_sock.getsockname()[1]}")

    def stop(self):
        self.running = False
        self.csv_queue.put(None)
        if hasattr(self, 'csv_file') and not self.csv_file.closed:
            self.csv_file.close()

    def _log_metric(self, direction, latency_ms, msg_id, key_id, status):
        cpu_pct = f"{psutil.cpu_percent(interval=0.1):.1f}"
        timestamp = time.strftime("%H:%M:%S")
        line = f"{timestamp},{direction},{latency_ms:.3f},{msg_id},{key_id},{cpu_pct},{status}\n"
        self.csv_queue.put(line)

    def _csv_writer_loop(self):
        while True:
            line = self.csv_queue.get()
            if line is None:
                break
            self.csv_file.write(line)
            self.csv_file.flush()

    def _app_to_rf_loop(self):
        while self.running:
            try:
                t0 = time.perf_counter()
                data, addr = self.app_sock.recvfrom(4096)
                self.app_peer_addr = addr

                encrypted = self.crypto.encrypt(data)
                self.rf_sock.sendto(encrypted, self.rf_send_addr)

                latency = (time.perf_counter() - t0) * 1000
                msg_id = extract_mavlink_msgid(data)
                self._log_metric("OUTBOUND", latency, msg_id, self.crypto.key_id, "ENCRYPTED")
            except socket.timeout:
                continue
            except Exception:
                pass

    def _rf_to_app_loop(self):
        while self.running:
            try:
                t0 = time.perf_counter()
                data, addr = self.rf_sock.recvfrom(4096)

                decrypted = self.crypto.decrypt(data)
                latency = (time.perf_counter() - t0) * 1000

                if decrypted:
                    if self.app_peer_addr:
                        self.app_sock.sendto(decrypted, self.app_peer_addr)
                        msg_id = extract_mavlink_msgid(decrypted)
                        self._log_metric("INBOUND", latency, msg_id, self.crypto.key_id, "OK")
                    else:
                        self._log_metric("INBOUND", latency, "N/A", self.crypto.key_id, "NO_PEER")
                else:
                    self._log_metric("INBOUND", latency, "N/A", self.crypto.key_id, "DROP_REPLAY")
            except socket.timeout:
                continue
            except Exception:
                pass


class BidirectionalRFAttacker(threading.Thread):
    def __init__(self, listen_port_1, forward_port_1, listen_port_2, forward_port_2):
        super().__init__()
        self.sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock1.bind(("127.0.0.1", listen_port_1))
        self.sock1.settimeout(0.1)
        self.fwd1 = ("127.0.0.1", forward_port_1)

        self.sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock2.bind(("127.0.0.1", listen_port_2))
        self.sock2.settimeout(0.1)
        self.fwd2 = ("127.0.0.1", forward_port_2)

        self.buffer1 = deque(maxlen=20)
        self.buffer2 = deque(maxlen=20)
        self.replays_injected = 0
        self.daemon = True

    def run(self):
        threading.Thread(target=self._sniff_and_inject, args=(self.sock1, self.buffer1, self.fwd1), daemon=True).start()
        threading.Thread(target=self._sniff_and_inject, args=(self.sock2, self.buffer2, self.fwd2), daemon=True).start()
        while True:
            time.sleep(1)

    def _sniff_and_inject(self, sock, buffer, fwd_addr):
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                buffer.append(data)
                sock.sendto(data, fwd_addr)

                if random.random() < 0.15 and len(buffer) >= 3:
                    old = random.choice(list(buffer)[:-1])
                    sock.sendto(old, fwd_addr)
                    self.replays_injected += 1
            except socket.timeout:
                continue
