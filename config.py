INSTANCE_NAME = "api_app"
WINDOW_SECONDS = 10
PACKET_IN_THRESHOLD = 10  # Lowered for 3-switch test setup
CONTROLLER_NAME = "self healing sdn api app"

# Additional constants for controller behavior
SOURCE_RATE_THRESHOLD = 5  # Lowered for testing
TRUST_THRESHOLD = 3
DROP_IDLE_TIMEOUT = 30  # Increased for testing observation
DROP_HARD_TIMEOUT = 60
DROP_PRIORITY = 100
LEARNING_PRIORITY = 1


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
        "controller_cpu_percent": 0.0,
        "learned_mac_entries": 0,
        "attack_detected": False,
        "packet_in_threshold": PACKET_IN_THRESHOLD,
    }