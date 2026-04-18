import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

from config import (
    INSTANCE_NAME, 
    WINDOW_SECONDS, 
    PACKET_IN_THRESHOLD, 
    CONTROLLER_NAME, 
)

from rest_controller import RestController

class SelfHealingSDNController(app_manager.RyuApp):
    """
    A simple OpenFlow 1.3 learning switch with custom REST API endpoints.

    Main features:
    - Learns MAC-to-port mappings like a normal L2 switch
    - Installs flow entries after learning destinations
    - Tracks Packet-In events for monitoring
    - Exposes controller and topology information through REST
    """
    #print("debugging: in ryu app\n")
    # Use OpenFlow 1.3 for this controller
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        #print("DEBUG: app object id in __init__ =", id(self))
        super(SelfHealingSDNController, self).__init__(*args, **kwargs)

        # register REST controller
        wsgi = kwargs['wsgi']
        wsgi.register(RestController, {INSTANCE_NAME: self})

        # Track MAC address to switch port mappings per switch
        # mac_to_port[dpid][mac] = port_no
        self.mac_to_port = defaultdict(dict)

        # datapaths[dpid] = datapath object
        self.datapaths = {}

        # host learning table:
        # hosts[mac] = {
        #   "ip": "10.0.0.x" or None,
        #   "dpid": <switch id>,
        #   "port": <port no>,
        #   "last_seen": <timestamp>
        # }
        self.hosts = {}
        
        # Packet-In stats
        self.start_time = time.time()   # controller uptime start
        self.packet_in_count = 0        # "packet_in" counter
        self.packet_in_events = deque() # timestamps of recent PI events
        
        # attack detection threshold
        self.packet_in_threshold = PACKET_IN_THRESHOLD
        self.attack_detected = False
        self.mitigation_start_time = None
        self.last_detection_time = None
        self.mitigated_drop_count = 0 # count of dropped packets during mitigation
        
        self.logger.info("self healing sdn api app started")
    
    def _cleanup_old_packets_in_events(self, window_seconds=WINDOW_SECONDS):
        """ Keep only recent PI timestamps inside the rolling time window (default=10 secs) """    
        
        now = time.time()
        while self.packet_in_events and (now - self.packet_in_events[0] > window_seconds):
            self.packet_in_events.popleft()
             
    def _packet_in_rate(self, window_seconds=WINDOW_SECONDS):
        """ Keep PI rate over the last window_seconds """     
        
        self._cleanup_old_packets_in_events(window_seconds=window_seconds)
        return len(self.packet_in_events) / float(window_seconds)
    
    def _update_attack_status(self):
        """ Update attack detection status based on PI rate """
        
        current_rate = self._packet_in_rate(window_seconds=WINDOW_SECONDS)
        if current_rate > self.packet_in_threshold:
            # first time detecting attack, note the time
            if self.attack_detected == False:
                self.last_detection_time = time.time()
            self.attack_detected = True
        else:
            self.attack_detected = False
            
    def _note_mitigation_start(self):
        """ Note the start time of mitigation
        """
        self.mitigation_start_time = time.time()

    def get_stats(self):
        """ Returns controller-level stats
        """
        
        uptime = time.time() - self.start_time
        packet_in_rate = self._packet_in_rate(window_seconds=WINDOW_SECONDS)
        self._update_attack_status()
        
        return {
            "controller": "self healing sdn api app",
            "uptime_seconds": round(uptime, 2),
            "connected_switches": len(self.datapaths),
            "known_hosts": len(self.hosts),
            "packet_in_total": self.packet_in_count,
            "packet_in_rate": round(packet_in_rate, 2) if uptime > 0 else 0,
            "learned_mac_entries": sum(len(macs) for macs in self.mac_to_port.values()),
            "attack_detected": self.attack_detected,
            "packet_in_threshold": self.packet_in_threshold,
            "mitigated_drop_count": self.mitigated_drop_count,
        }
        
    def get_switches(self):
        """ Return a list of connected switches
        """
        switches = []
        for dpid, dp in self.datapaths.items():
            switches.append({
                "dpid": dpid
            })
        return switches
    
    def get_hosts(self):
        """ Return a list of learned hosts
        """
        hosts = []
        for mac, info in self.hosts.items():
            hosts.append({
                "mac": mac,
                "ip": info.get("ip"),
                "dpid": info.get("dpid"),
                "port": info.get("port"),
                "last_seen": round(info.get("last_seen", 0), 2)
            })
        return hosts

    def get_flows_summary(self):
        """ Return a simple flow summary from learned MAC tables.
        This is not a true switch flow dump; it is a summary of what the
        learning switch knows and has likely installed.
        """
        flows = []
        for dpid, mac_table in self.mac_to_port.items():
            for mac, port in mac_table.items():
                flows.append({
                    "dpid": dpid,
                    "match_dst_mac": mac,
                    "output_port": port
                })
        return flows
    
    def reset_counters(self):
        """ Reset controller counters
        """
        self.start_time = time.time()
        self.packet_in_count = 0
        self.packet_in_events.clear()
        self.attack_detected = False
        self.mitigation_start_time = None
        self.last_detection_time = None
        self.mitigated_drop_count = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath  # ID current datapath
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry so unmatched packets go to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("Installed table-miss flow on switch %s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # Build and send a flow mod message to the switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority, 
                match=match, 
                instructions=inst
                )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, 
                priority=priority,
                match=match, 
                instructions=inst
                )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def state_change_handler(self, ev):
        """ Keep track of connected datapaths

        Args:
            self (_type_): controller
            ev (_type_): event
        """
        datapath = ev.datapath
        
        # update current datapath to list of datapaths
        if datapath is not None:
            self.datapaths[datapath.id] = datapath
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle Packet-In events from switches.

        This function:
        - increments Packet-In counters
        - learns source MAC to input port
        - learns host location
        - installs destination flow entries when possible
        - forwards packets normally like a learning switch
        """
        #print("debugging: packet in handler called\n")

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        
        # PI stats
        self.packet_in_count += 1 # "packet in" count increase
        self.packet_in_events.append(time.time())   # update event list with this event's timestamp
        self._update_attack_status()
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore LLDP packets used for topology discovery
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        
        dst = eth.dst
        src = eth.src

        # checking if the soruce is already known
        source_known = src in self.hosts

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = None
        
        if ipv4_pkt:
            src_ip = ipv4_pkt.src
        
        # drop unknown sources during attack mode
        if self.attack_detected and not source_known:
            self.mitigated_drop_count += 1
            self.logger.warning(
                "Mitigation: dropping unknown source %s on switch=%s port=%s during attack mode",
                src, dpid, in_port
            )
            return
        
        # Record host location
        self.hosts[src] = {
            "ip": src_ip,
            "dpid": dpid,
            "port": in_port,
            "last_seen": time.time()
        }                

        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("Packet in: switch=%s src=%s dst=%s in_port=%s", dpid, src, dst, in_port)

        # learn the source MAC address and the port it came from
        self.mac_to_port[dpid][src] = in_port

        # if destination MAC is known, send to that port, otherwise flood
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a forwarding rule for learned hosts to avoid future controller hops
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath=datapath, 
                    priority=1, 
                    match=match, 
                    actions=actions,
                    buffer_id=msg.buffer_id
                )
                return
            else:
                self.add_flow(
                    datapath=datapath, 
                    priority=1, 
                    match=match, 
                    actions=actions
                )
                
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=msg.buffer_id,
            in_port=in_port, 
            actions=actions, 
            data=data
        )
        datapath.send_msg(out)