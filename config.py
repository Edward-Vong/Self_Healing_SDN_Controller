INSTANCE_NAME = "api_app"
WINDOW_SECONDS = 10
PACKET_IN_THRESHOLD = 800  # ~62% of observed 1300 PI/s ceiling; leaves headroom for mitigation logic
CONTROLLER_NAME = "self healing sdn api app"

# Additional constants for controller behavior
SOURCE_RATE_THRESHOLD = 50  # Any single source >50 PI/s in 10s window is anomalous
TRUST_THRESHOLD = 3
MITIGATION_ENABLED = True
DROP_IDLE_TIMEOUT = 30  # Increased for testing observation
DROP_HARD_TIMEOUT = 60
DROP_PRIORITY = 100
LEARNING_PRIORITY = 1

# Mitigation manager constants
ATTACK_METER_RATE = 100  # Rate limit for attack flows (packets per second)
ESCALATION_THRESHOLD_SECONDS = 30  # Escalate meter to drop after this duration
RECOVERY_WINDOW_SECONDS = 60  # Total time for gradual recovery
HOLDDOWN_WINDOWS = 2  # Keep attack_detected=True for this many WINDOW_SECONDS after rate drops
MITIGATION_MIN_ACTIVE_WINDOWS = 2  # Keep mitigation active for at least this many WINDOW_SECONDS once triggered
RECOVERY_QUIET_WINDOWS = 2  # Require this many WINDOW_SECONDS of quiet before entering recovery


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
        "mitigation_enabled": MITIGATION_ENABLED,
        "mitigation_active": False,
        "attack_detected": False,
        "packet_in_threshold": PACKET_IN_THRESHOLD,
    }