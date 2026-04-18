from collections import defaultdict

INSTANCE_NAME = "api_app"
WINDOW_SECONDS = 10
PACKET_IN_THRESHOLD = 100
ATTACK_PACKETS = 200
CONTROLLER_NAME = "self healing sdn api app"


def default_host_record():
    return {
        "ip": None,
        "dpid": None,
        "port": None,
        "last_seen": 0.0,
    }


def default_stats_response():
    return {
        "controller": CONTROLLER_NAME,
        "uptime_seconds": 0.0,
        "connected_switches": 0,
        "known_hosts": 0,
        "packet_in_total": 0,
        "packet_in_rate": 0.0,
        "learned_mac_entries": 0,
        "attack_detected": False,
        "packet_in_threshold": PACKET_IN_THRESHOLD,
    }