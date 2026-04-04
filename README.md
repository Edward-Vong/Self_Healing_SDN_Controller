# Self-Healing SDN Controller (Ryu)

A simple starter SDN controller built on the Ryu framework. This repository is intentionally minimal so you can extend the self-healing logic later.

## What is included

- `src/ryu_self_healing_controller.py`: A basic Ryu app using OpenFlow 1.3.
- `requirements.txt`: Ryu dependency.
- `build.bat` / `build.sh`: install dependencies and compile the source.
- `run.bat` / `run.sh`: launch the controller with `ryu-manager`.

## Setup

Install dependencies:

Windows:
```bat
build.bat
```

Linux/macOS:
```bash
./build.sh
```

## Run the controller

Windows:
```bat
run.bat
```

Linux/macOS:
```bash
./run.sh
```

## How it works

This controller:

- uses OpenFlow 1.3
- installs a table-miss flow entry on switch connect
- handles `PACKET_IN` events
- logs packet details
- forwards packets by flooding when the destination is unknown

### Next steps

Add detection and mitigation logic for self-healing behavior, such as:

- monitoring link or host failures
- detecting DDoS or anomalous traffic
- dynamically updating flows to isolate bad traffic
