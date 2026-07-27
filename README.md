# UAV/GCS Secure Communication System

## Overview

Software-In-The-Loop (SITL) UAV command-and-control system with encrypted MAVLink communication over UDP. Three independent modules connected through a shared cryptographic layer.

## Architecture

```
gcs_interactive_win.py          uav_interactive_linux.py
       |                                |
  [keyboard]                     [altitude controller]
       |                                |
  CryptoBridge.encrypt()          CryptoBridge.decrypt()
       |                                |
       +------ UDP 14550 ------+
                    |
              crypto_bridge.py
          (ASCON + HMAC-SHA256)
```

## Components

### crypto_bridge.py
Standalone encryption module. No network or MAVLink dependencies.
- ASCON authenticated encryption (encrypt-then-MAC)
- HMAC-SHA256 key derivation from a shared 32-byte master secret
- Per-packet replay window (64-entry sliding window)
- Automatic key rotation after 100 encrypts
- Thread-safe via `threading.RLock`

### uav_interactive_linux.py
UAV simulator. Runs on Linux VM, listens on `0.0.0.0:14550`.
- Receives encrypted commands, decrypts, executes (ascend/descend/stop/move)
- Sends encrypted telemetry (GLOBAL_POSITION_INT) back to GCS
- Two threads: main command loop + altitude controller daemon
- Exits on shutdown signal (command=0, param1=99)

### gcs_interactive_win.py
GCS controller. Runs on Windows, connects to UAV via UDP.
- Sends encrypted commands via keyboard input
- Receives and displays real-time telemetry
- Two threads: keyboard polling + telemetry listener daemon
- Exits on ESC (sends shutdown signal)

### test_system.py
18-test suite (unit + integration + system). Connects to live UAV.

## Running

**Start the UAV:**
```bash
python3 uav_interactive_linux.py
```

**Start the GCS (Windows):**
```bash
python3 gcs_interactive_win.py
```

**Run tests (Windows):**
```bash
python3 test_system.py
```

## GCS Controls

| Key   | Action                             |
|-------|------------------------------------|
| UP    | Toggle ascend on/off               |
| DOWN  | Toggle descend on/off              |
| LEFT  | Move west (longitude -0.0001)      |
| RIGHT | Move east (longitude +0.0001)      |
| W     | Move north (latitude +0.0001)      |
| S     | Move south (latitude -0.0001)      |
| ESC   | Send shutdown signal + exit        |

## Command Encoding

All flight commands use MAVLink `COMMAND_LONG` with command ID 176:

| param1 | param2 | Action        |
|--------|--------|---------------|
| 1      | 0      | Start ascend  |
| -1     | 0      | Start descend |
| 0      | 0      | Stop          |
| 2      | 0      | Move north    |
| -2     | 0      | Move south    |
| 0      | 1      | Move east     |
| 0      | -1     | Move west     |

Shutdown: command=0, param1=99 (separate command ID).

## Packet Format

```
+----------+----------+-------+---------+------------+-----+
| key_id   | seq      | nonce | ct_len  | ciphertext | tag |
| 4 bytes  | 8 bytes  | 16 B  | 4 bytes | variable   | 16B |
+----------+----------+-------+---------+------------+-----+
```

- **key_id**: current encryption key identifier
- **seq**: monotonically increasing sequence number (anti-replay)
- **nonce**: random 16-byte nonce (first 4 bytes = key_id)
- **ciphertext**: ASCON-encrypted payload
- **tag**: 16-byte ASCON authentication tag

## Security Properties

- **Confidentiality**: ASCON-128 authenticated encryption
- **Integrity**: 16-byte authentication tag per packet
- **Replay protection**: 64-entry sliding window per receiver
- **Key rotation**: automatic after 100 encrypts, ±1 tolerance for seamless transition
- **Attack resistance**: wrong-key, malformed, and replayed packets silently rejected

## Test Coverage

| Category | Tests | Scope |
|----------|-------|-------|
| Unit     | TC-01 to TC-06b | CryptoBridge only (no network) |
| Integration | TC-07 to TC-12 | GCS-to-UAV command/response |
| System   | TC-13 to TC-17 | Attack scenarios + latency benchmarks |

## Dependencies

- Python 3.11+
- `pymavlink` (MAVLink message encoding/parsing)
- `ascon` (ASCON-128 encryption)
- `keyboard` (GCS interactive controls)
