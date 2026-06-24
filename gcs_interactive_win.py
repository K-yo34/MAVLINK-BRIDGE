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
import threading
import csv
from datetime import datetime
from pymavlink import mavutil
from crypto_bridge import CryptoBridge

try:
    import keyboard
except ImportError:
    print("keyboard library not found. Run: pip install keyboard")
    sys.exit(1)

DEVICE_B_IP = "10.200.28.26"
UAV_LISTEN_PORT = 14550

def main():
    print(f"GCS targeting UAV at {DEVICE_B_IP}:{UAV_LISTEN_PORT}")
    print("Controls: UP=alt_up, DOWN=alt_down, LEFT=move_left, RIGHT=move_right, ESC=exit")

    secret = b"my_super_secret_capstone_key_32_bytes!"
    bridge = CryptoBridge(secret)
    mav = mavutil.mavlink.MAVLink(None, srcSystem=2, srcComponent=1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)

    csv_file = open("gcs_mission_log.csv", "w", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Timestamp", "Direction", "Event", "Altitude", "Status"])

    def telemetry_listener():
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                decrypted = bridge.decrypt(data)
                if decrypted:
                    msg = mav.parse_char(decrypted)
                    if msg and msg.get_type() == 'GLOBAL_POSITION_INT':
                        alt = msg.alt / 1000.0
                        lat = msg.lat / 1e7
                        lon = msg.lon / 1e7
                        print(f"\n[RECV] telemetry: alt={alt:.1f}m, lat={lat:.5f}, lon={lon:.5f}")

                        ts = datetime.now().strftime("%H:%M:%S")
                        csv_writer.writerow([ts, "INBOUND", "TELEMETRY_RECEIVED", f"{alt:.1f}", "AUTHENTICATED"])
                        csv_file.flush()
                    else:
                        print(f"\n[RECV] decrypted but unrecognized message")
                else:
                    print(f"\n[RECV] decryption FAILED (replay/tamper)")
                    ts = datetime.now().strftime("%H:%M:%S")
                    csv_writer.writerow([ts, "INBOUND", "DECRYPTION_FAILED", "N/A", "BLOCKED"])
                    csv_file.flush()
            except socket.timeout:
                continue
            except Exception:
                pass

    threading.Thread(target=telemetry_listener, daemon=True).start()
    print("Ready. Press arrow keys to control UAV...")

    try:
        while True:
            cmd_to_send = None
            action_name = ""

            if keyboard.is_pressed('up'):
                action_name = "ALT_UP"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 1, 0, 0, 0, 0, 0, 0)
            elif keyboard.is_pressed('down'):
                action_name = "ALT_DOWN"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, -1, 0, 0, 0, 0, 0, 0)
            elif keyboard.is_pressed('left'):
                action_name = "MOVE_LEFT"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 0, -1, 0, 0, 0, 0, 0)
            elif keyboard.is_pressed('right'):
                action_name = "MOVE_RIGHT"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 0, 1, 0, 0, 0, 0, 0)
            elif keyboard.is_pressed('esc'):
                print("Exiting GCS...")
                break

            if cmd_to_send:
                plaintext = cmd_to_send.pack(mav)
                print(f"\n[SEND] command: {action_name}")

                encrypted = bridge.encrypt(plaintext)
                print(f"       encrypted hex: {encrypted[:32].hex(' ').upper()}...")

                with open("captured_packet.bin", "wb") as f:
                    f.write(encrypted)

                sock.sendto(encrypted, (DEVICE_B_IP, UAV_LISTEN_PORT))

                ts = datetime.now().strftime("%H:%M:%S")
                csv_writer.writerow([ts, "OUTBOUND", action_name, "N/A", "ENCRYPTED"])
                csv_file.flush()

                time.sleep(0.25)

    except KeyboardInterrupt:
        print("Exiting GCS...")
    finally:
        csv_file.close()

if __name__ == "__main__":
    main()
