import os
import sys
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
_VENV_SITE = os.path.join(os.path.dirname(_here), 'capstone 2', 'env', 'Lib', 'site-packages')
if os.path.isdir(_VENV_SITE) and _VENV_SITE not in sys.path:
    sys.path.insert(0, _VENV_SITE)
for _ver in ['312', '311', '310', '313']:
    _sp = os.path.join(f'C:/Python{_ver}', 'Lib', 'site-packages')
    if os.path.isdir(_sp) and _sp not in sys.path:
        sys.path.insert(0, _sp)

import time
import socket
import csv
import threading
from datetime import datetime
from pymavlink import mavutil
from crypto_bridge import CryptoBridge

LOCAL_LISTEN_PORT = 14550

def main():
    print(f"UAV listening on 0.0.0.0:{LOCAL_LISTEN_PORT}")

    secret = b"my_super_secret_capstone_key_32_bytes!"
    bridge = CryptoBridge(secret)
    mav = mavutil.mavlink.MAVLink(None, srcSystem=1, srcComponent=1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LOCAL_LISTEN_PORT))
    sock.settimeout(1.0)

    current_alt = 150.0
    current_lat = 37.7749
    current_lon = -122.4194
    target_alt_change = 0
    last_addr = None
    crashed = False

    csv_file = open("telemetry_log.csv", "w", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Timestamp", "Command", "Alt", "Lat", "Lon", "Status"])

    def send_telemetry():
        nonlocal current_alt, current_lat, current_lon, last_addr, crashed
        telem_msg = mav.global_position_int_encode(
            int(time.time() * 1000) & 0xFFFFFFFF,
            int(current_lat * 1e7),
            int(current_lon * 1e7),
            int(current_alt * 1000),
            0, 0, 0, 0, 0
        )
        telem_bytes = telem_msg.pack(mav)
        encrypted_response = bridge.encrypt(telem_bytes)
        print(f"[UAV] encrypted telemetry: alt={current_alt:.1f}m, hex={encrypted_response[:32].hex(' ').upper()}...")
        if last_addr:
            sock.sendto(encrypted_response, last_addr)
        csv_writer.writerow([datetime.now().strftime("%H:%M:%S"), "TELEMETRY", f"{current_alt:.2f}", f"{current_lat:.5f}", f"{current_lon:.5f}", "AUTHENTICATED"])
        csv_file.flush()

    def altitude_controller():
        nonlocal current_alt, target_alt_change, crashed
        last_telem_time = 0
        while True:
            if crashed:
                time.sleep(0.2)
                continue
            now = time.time()
            if target_alt_change > 0:
                current_alt += 2.0
                if now - last_telem_time >= 1.0:
                    send_telemetry()
                    last_telem_time = now
                time.sleep(0.2)
            elif target_alt_change < 0:
                current_alt -= 2.0
                if now - last_telem_time >= 2.0:
                    send_telemetry()
                    last_telem_time = now
                if current_alt <= 1000.0:
                    print("WARNING: altitude low")
                if current_alt <= 0:
                    print("CRASHED: altitude reached 0m")
                    crashed = True
                    target_alt_change = 0
                    csv_writer.writerow([datetime.now().strftime("%H:%M:%S"), "CRASH", "0", f"{current_lat:.5f}", f"{current_lon:.5f}", "CRASHED"])
                    csv_file.flush()
                time.sleep(0.2)
            else:
                if now - last_telem_time >= 2.0:
                    send_telemetry()
                    last_telem_time = now
                time.sleep(0.2)

    threading.Thread(target=altitude_controller, daemon=True).start()

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                last_addr = addr

                decrypted = bridge.decrypt(data)

                if decrypted:
                    msg = mav.parse_char(decrypted)
                    if msg and msg.get_type() == 'COMMAND_LONG':
                        if msg.command == 0 and msg.param1 == 99:
                            print("[UAV] received shutdown signal from GCS")
                            break
                        if msg.command != 176:
                            continue
                        param1 = msg.param1
                        param2 = msg.param2
                        command_desc = "NONE"

                        if param1 > 0 and not crashed:
                            target_alt_change = 10
                            command_desc = "START_ASCEND"
                        elif param1 < 0 and not crashed:
                            target_alt_change = -10
                            command_desc = "START_DESCEND"
                        elif param1 == 0 and param2 == 0:
                            target_alt_change = 0
                            command_desc = "STOP"
                            send_telemetry()

                        if param2 > 0:
                            current_lon += 0.0001
                            command_desc = "MOVE_RIGHT"
                            send_telemetry()
                        elif param2 < 0:
                            current_lon -= 0.0001
                            command_desc = "MOVE_LEFT"
                            send_telemetry()

                        if crashed:
                            print("[UAV] UAV is crashed, ignoring movement commands")
                        else:
                            print(f"[UAV] command: {command_desc} | alt: {current_alt:.1f}m")

                        timestamp = datetime.now().strftime("%H:%M:%S")
                        csv_writer.writerow([timestamp, command_desc, f"{current_alt:.2f}", f"{current_lat:.5f}", f"{current_lon:.5f}", "AUTHENTICATED"])
                        csv_file.flush()

                else:
                    print(f"[UAV] attack blocked: decryption FAILED (replay/tamper)")
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    csv_writer.writerow([timestamp, "REPLAY_ATTACK", "N/A", "N/A", "N/A", "DROP_REPLAY"])
                    csv_file.flush()

            except socket.timeout:
                continue

    except KeyboardInterrupt:
        print("Shutting down UAV...")
    finally:
        csv_file.close()

if __name__ == "__main__":
    main()
