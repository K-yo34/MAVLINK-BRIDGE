# =============================================================================
# gcs_interactive_win.py  (SIMPLE COMMENTS - ONLY ON MAIN LOGIC)
# Original code logic is UNCHANGED.
# This is the Ground Control Station - your remote control for the drone.
# =============================================================================

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

DEVICE_B_IP = "192.168.1.76"   # the UAV's IP address
UAV_LISTEN_PORT = 14550        # the port both sides use

def main():
    print(f"GCS targeting UAV at {DEVICE_B_IP}:{UAV_LISTEN_PORT}")
    print("Controls: UP=toggle ascend, DOWN=toggle descend, LEFT=move_left, RIGHT=move_right, W=north, S=south, ESC=exit")

    # Set up security + network
    secret = b"my_super_secret_capstone_key_32_bytes!"   # shared password (SAME as UAV)
    bridge = CryptoBridge(secret)
    mav = mavutil.mavlink.MAVLink(None, srcSystem=2, srcComponent=1)  # 2 = GCS
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)

    ascending = False
    descending = False

    # Log file (your capstone evidence)
    csv_file = open("gcs_mission_log.csv", "w", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["Timestamp", "Direction", "Event", "Altitude", "Status"])

    def telemetry_listener():
        # Background thread: listens for the UAV's position updates
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                decrypted = bridge.decrypt(data)   # check the packet

                if decrypted:                      # packet is safe
                    msg = mav.parse_char(decrypted)
                    if msg and msg.get_type() == 'GLOBAL_POSITION_INT':
                        alt = msg.alt / 1000.0     # mm -> meters
                        lat = msg.lat / 1e7        # fixed point -> degrees
                        lon = msg.lon / 1e7
                        print(f"\n[RECV] telemetry: alt={alt:.1f}m, lat={lat:.5f}, lon={lon:.5f}")

                        if alt > 35000.0:
                            print("WARNING: altitude exceeds 100m")
                        if alt <= 0:
                            print("CRASHED: UAV crashed")

                        ts = datetime.now().strftime("%H:%M:%S")
                        csv_writer.writerow([ts, "INBOUND", "TELEMETRY_RECEIVED", f"{alt:.1f}", "AUTHENTICATED"])
                        csv_file.flush()
                    else:
                        print(f"\n[RECV] decrypted but unrecognized message")
                else:
                    # decrypt failed = attack blocked (replay/tamper)
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
        # Main loop: read keyboard -> make command -> encrypt -> send
        while True:
            cmd_to_send = None
            action_name = ""

            if keyboard.is_pressed('up'):
                ascending = not ascending       # toggle climb ON/OFF
                if ascending:
                    descending = False
                    action_name = "START_ASCEND"
                    cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 1, 0, 0, 0, 0, 0, 0)
                else:
                    action_name = "STOP"
                    cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 0, 0, 0, 0, 0, 0, 0)
                time.sleep(0.3)

            elif keyboard.is_pressed('down'):
                descending = not descending     # toggle descend ON/OFF
                if descending:
                    ascending = False
                    action_name = "START_DESCEND"
                    cmd_to_send = mav.command_long_encode(1, 1, 176, 0, -1, 0, 0, 0, 0, 0, 0)
                else:
                    action_name = "STOP"
                    cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 0, 0, 0, 0, 0, 0, 0)
                time.sleep(0.3)

            elif keyboard.is_pressed('left'):
                action_name = "MOVE_LEFT"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 0, -1, 0, 0, 0, 0, 0)
                time.sleep(0.25)

            elif keyboard.is_pressed('right'):
                action_name = "MOVE_RIGHT"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 0, 1, 0, 0, 0, 0, 0)
                time.sleep(0.25)

            elif keyboard.is_pressed('w'):
                action_name = "MOVE_NORTH"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, 2, 0, 0, 0, 0, 0, 0)
                time.sleep(0.25)

            elif keyboard.is_pressed('s'):
                action_name = "MOVE_SOUTH"
                cmd_to_send = mav.command_long_encode(1, 1, 176, 0, -2, 0, 0, 0, 0, 0, 0)
                time.sleep(0.25)

            elif keyboard.is_pressed('esc'):
                print("Exiting GCS...")
                # special shutdown command (cmd 0, param 99)
                shutdown_cmd = mav.command_long_encode(1, 1, 0, 0, 99, 0, 0, 0, 0, 0, 0)
                sock.sendto(bridge.encrypt(shutdown_cmd.pack(mav)), (DEVICE_B_IP, UAV_LISTEN_PORT))
                break

            if cmd_to_send:
                plaintext = cmd_to_send.pack(mav)
                print(f"\n[SEND] command: {action_name}")

                encrypted = bridge.encrypt(plaintext)   # SCRAMBLE it
                print(f"       encrypted hex: {encrypted[:32].hex(' ').upper()}...")

                # Save this packet = replay attack evidence
                with open("captured_packet.bin", "wb") as f:
                    f.write(encrypted)

                sock.sendto(encrypted, (DEVICE_B_IP, UAV_LISTEN_PORT))

                ts = datetime.now().strftime("%H:%M:%S")
                csv_writer.writerow([ts, "OUTBOUND", action_name, "N/A", "ENCRYPTED"])
                csv_file.flush()

            time.sleep(0.05)

    except KeyboardInterrupt:
        print("Exiting GCS...")
        try:
            shutdown_cmd = mav.command_long_encode(1, 1, 0, 0, 99, 0, 0, 0, 0, 0, 0)
            sock.sendto(bridge.encrypt(shutdown_cmd.pack(mav)), (DEVICE_B_IP, UAV_LISTEN_PORT))
        except Exception:
            pass
    finally:
        csv_file.close()

if __name__ == "__main__":
    main()
