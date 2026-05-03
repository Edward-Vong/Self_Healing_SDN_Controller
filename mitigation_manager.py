"""
Mitigation manager — installs meter and drop rules on switches.
"""
import time
from ryu.ofproto import ofproto_v1_3


class MitigationManager:
    """Manages switch-level rate-limiting and drop rules"""
    
    METER_ID_BASE = 100  # Start meter IDs from 100 to avoid conflicts
    
    def __init__(self, attack_state, logger, meter_rate=100):
        self.attack_state = attack_state
        self.logger = logger
        self.meter_rate = meter_rate  # pps (packets per second)
        self._meter_counter = self.METER_ID_BASE
    
    def _allocate_meter_id(self):
        """Allocate unique meter ID"""
        meter_id = self._meter_counter
        self._meter_counter += 1
        if self._meter_counter > 65535:  # OpenFlow meter ID limit
            self._meter_counter = self.METER_ID_BASE
        return meter_id
    
    def install_meter_on_port(self, datapath, in_port):
        """Install rate-limit meter on ingress port"""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Allocate meter ID
        meter_id = self._allocate_meter_id()
        
        # Create meter with drop band for excess traffic
        band = parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, rate=self.meter_rate)
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_PKTPS,  # Rate in packets per second
            meter_id=meter_id,
            bands=[band]
        )
        datapath.send_msg(meter_mod)
        
        # Install flow rule: traffic on in_port → meter
        match = parser.OFPMatch(in_port=in_port)
        meter_inst = parser.OFPInstructionMeter(meter_id)
        normal_action = parser.OFPActionOutput(ofproto.OFPP_NORMAL)
        inst = [
            meter_inst, 
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [normal_action])
        ]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=200,  # Higher than normal learning flows
            match=match,
            instructions=inst
        )
        datapath.send_msg(flow_mod)
        
        # Track meter
        self.attack_state.mark_meter_on_port(dpid, in_port, meter_id)
        self.logger.warning(f"Meter installed on dpid={dpid} port={in_port} meter_id={meter_id} rate={self.meter_rate} pps")
        return meter_id
    
    def install_drop_on_port(self, datapath, in_port):
        """Install hard drop rule on ingress port (escalation)"""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install flow rule: traffic on in_port → DROP (empty actions)
        match = parser.OFPMatch(in_port=in_port)
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_MODIFY_STRICT,  # Replace existing
            priority=200,
            match=match,
            instructions=[]  # Empty instructions = drop
        )
        datapath.send_msg(flow_mod)
        
        # Remove associated meter
        meter_id = self.attack_state.get_meter_id(dpid, in_port)
        if meter_id is not None:
            meter_mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                meter_id=meter_id
            )
            datapath.send_msg(meter_mod)
        
        self.attack_state.mark_escalated(dpid, in_port)
        self.logger.warning(f"Escalated to drop on dpid={dpid} port={in_port}")
    
    def remove_meter_on_port(self, datapath, in_port):
        """Remove meter rule from port (recovery)"""
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Delete meter
        meter_id = self.attack_state.get_meter_id(dpid, in_port)
        if meter_id is not None:
            meter_mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                meter_id=meter_id
            )
            datapath.send_msg(meter_mod)
        
        # Delete flow rule
        match = parser.OFPMatch(in_port=in_port)
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            match=match,
            priority=200
        )
        datapath.send_msg(flow_mod)
        
        self.attack_state.clear_port(dpid, in_port)
        self.logger.info(f"Meter removed on dpid={dpid} port={in_port}")
    
    def check_escalate_to_drop(self, datapaths, escalation_threshold_sec=30):
        """Check if any rate-limited port should escalate to drop"""
        for dpid, datapath in datapaths.items():
            for port in list(self.attack_state.get_rate_limited_ports(dpid)):
                if not self.attack_state.is_escalated(dpid, port):
                    duration = self.attack_state.get_attack_duration(dpid, port)
                    if duration > escalation_threshold_sec:
                        self.install_drop_on_port(datapath, port)
