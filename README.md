# Self-Healing SDN Controller

## Protecting the SDN Control Plane Against Packet-In Saturation Attacks

### Overview

This project implements a self-healing Software Defined Networking (SDN) controller using the Ryu OpenFlow framework. The controller detects abnormal Packet-In traffic caused by control-plane flooding attacks and applies mitigation strategies to protect controller availability while preserving legitimate traffic.

The system was designed and tested on CloudLab using Open vSwitch (OVS) bridges connected to a centralized Ryu controller.



## Installation

### Clone Repository
```
git clone https://github.com/Edward-Vong/Self_Healing_SDN_Controller
cd Self_Healing_SDN_Controller
```

### Python Dependencies
```
python3.8 -m pip install ryu
python3.8 -m pip install scapy
python3.8 -m pip install matplotlib
python3.8 -m pip install webob
```

### Install OpenvSwitch
```
sudo apt-get update
sudo apt-get install -y openvswitch-switch
```

## Install Traffic Tools
```
sudo apt-get install -y iperf
sudo apt-get install -y hping3
sudo apt-get install -y arping
```

## Topology
| Node       | Role                   |
| ---------- | ---------------------- |
| node-0     | Trusted traffic source |
| node-1     | Attacker               |
| node-2     | Victim                 |
| controller | Ryu SDN controller     |


## OVS Setup Example
Trusted Node (change accordingly for attacker (ovs-lan2)/victim (ovs-lan3 node)):
```
sudo ovs-vsctl add-br ovs-lan1
sudo ovs-vsctl add-port ovs-lan1 eth1
sudo ovs-vsctl add-port ovs-lan1 eth2

sudo ifconfig eth1 0
sudo ifconfig eth2 0

sudo ovs-vsctl set bridge ovs-lan1 stp_enable=true
sudo ovs-vsctl set-controller ovs-lan1 tcp:<controller-ip>:6653

sudo ifconfig ovs-lan1 10.10.10.1 netmask 255.255.255.0 up
```

## Running the Controller
Start the Ryu Self-Healing Controller on the controller node:
```
ryu-manager \
  --ofp-listen-host 0.0.0.0 \
  --ofp-tcp-listen-port 6653 \
  --observe-links \
  ryu_self_healing_controller.py
```

## Verify Controller Connectivity
```
curl http://127.0.0.1:8080/stats
```
Expected output:
```
{ 
  "connected_switches": 3
}
```

## Running Prerequisite Checks
```
bash experiment_scripts/check_prereqs.sh
```

## Running Experiments

### Quick Validation Check:
```
bash experiment_scripts/run_all_tests.sh \
  --controller http://127.0.0.1:8080 \
  --duration 75 \
  --attack-delay 15 \
  --attack-length 45 \
  --skip-saturation \
  --skip-size-sweep \
  --skip-rate-sweep \
  --clear-ovs off
```

### Full Experiment Suite:
```
bash experiment_scripts/run_all_tests.sh \
  --controller http://127.0.0.1:8080 \
  --duration 90 \
  --attack-delay 15 \
  --attack-length 45 \
  --clear-ovs off
```

## Generating Plots

### Plot All Runs:
```
bash experiment_scripts/run_all_tests.sh --replot
```

### Plot Cross-Run RTT Sweep:
```
python experiment_scripts/plot_rate_sweep_rtt.py results
```

## License
This project was developed for academic and research purposes.