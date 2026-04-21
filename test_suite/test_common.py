import requests


REST_TIMEOUT = 4


def _get_json(controller_api, path):
    try:
        response = requests.get(controller_api + path, timeout=REST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"  [REST] {path} failed: {e}")
        return None


def _post_json(controller_api, path, payload=None):
    try:
        response = requests.post(controller_api + path, json=payload, timeout=REST_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"  [REST] {path} failed: {e}")
        return None


def get_stats(controller_api):
    return _get_json(controller_api, "/stats")


def get_attack_metrics(controller_api):
    return _get_json(controller_api, "/attack/metrics")


def parse_cpu_percent(stats, cpu_key="controller_cpu_percent"):
    value = stats.get(cpu_key)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().rstrip("%")
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def reset_controller(controller_api):
    return _post_json(controller_api, "/config/reset") is not None


def set_threshold(controller_api, value):
    return _post_json(controller_api, "/config/threshold", {"threshold": value}) is not None


def set_mitigation_enabled(controller_api, enabled):
    body = _post_json(controller_api, "/config/mitigation", {"enabled": enabled})
    if body is None:
        return False
    return body.get("mitigation_enabled") is enabled