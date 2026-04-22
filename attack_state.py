"""
Attack state tracker — tracks per-port/per-source attack metadata.
"""
import time
from collections import defaultdict


class AttackState:
    """Tracks attack metrics per port and source"""
    
    def __init__(self, logger):
        self.logger = logger
        # port_attack_start[dpid][port] = timestamp when attack started on that port
        self.port_attack_start = defaultdict(dict)
        # port_escalated[dpid][port] = True if meter escalated to drop
        self.port_escalated = defaultdict(dict)
        # port_meter_ids[dpid][port] = meter_id for that port
        self.port_meter_ids = defaultdict(dict)
        # rate_limited_ports[dpid] = set of ports with active meters
        self.rate_limited_ports = defaultdict(set)
        
    def mark_attack_on_port(self, dpid, port):
        """Mark when attack starts on a port"""
        if port not in self.port_attack_start[dpid]:
            self.port_attack_start[dpid][port] = time.time()
            self.logger.info(f"Attack marked on dpid={dpid} port={port}")
    
    def mark_meter_on_port(self, dpid, port, meter_id):
        """Record meter installation on port"""
        self.port_meter_ids[dpid][port] = meter_id
        self.rate_limited_ports[dpid].add(port)
    
    def mark_escalated(self, dpid, port):
        """Mark when meter escalates to drop"""
        self.port_escalated[dpid][port] = True
    
    def is_escalated(self, dpid, port):
        """Check if port's attack has escalated to drop"""
        return self.port_escalated.get(dpid, {}).get(port, False)
    
    def get_attack_duration(self, dpid, port):
        """Get how long attack has been on this port (seconds)"""
        if port not in self.port_attack_start.get(dpid, {}):
            return 0.0
        return time.time() - self.port_attack_start[dpid][port]
    
    def get_meter_id(self, dpid, port):
        """Get meter ID for port"""
        return self.port_meter_ids.get(dpid, {}).get(port)
    
    def get_rate_limited_ports(self, dpid):
        """Get all ports with active meters on a switch"""
        return self.rate_limited_ports.get(dpid, set())
    
    def clear_port(self, dpid, port):
        """Clear state for a port (e.g., after recovery)"""
        self.port_attack_start[dpid].pop(port, None)
        self.port_escalated[dpid].pop(port, None)
        self.port_meter_ids[dpid].pop(port, None)
        self.rate_limited_ports[dpid].discard(port)
    
    def clear_all(self):
        """Full reset"""
        self.port_attack_start.clear()
        self.port_escalated.clear()
        self.port_meter_ids.clear()
        self.rate_limited_ports.clear()
