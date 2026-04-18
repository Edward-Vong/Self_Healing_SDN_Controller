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

        # mitigation stats
        self.mitigated_drop_count = 0 # count of dropped packets during mitigation
        self.mitigated_sources = defaultdict(int) # count of mitigated packets per source MAC

        self.source_packet_counts = defaultdict(int)
        self.source_last_reset = time.time()
        self.source_rate_threshold = 50  # small number for testing

        # drop counters for unknown and over-rate sources during attack mode
        self.dropped_unknown_count = 0
        self.dropped_overrate_count = 0

        # statistics for source trust evaluation
        self.source_seen_counts = defaultdict(int)
        self.trusted_sources = set()
        self.trust_threshold = 3  # number of sightings before trust
        
        self.logger.info("self healing sdn api app started")

    # moved reset_counters closer to initialization because it was really annoying scrolling back and forth
    def reset_counters(self):
        """ Reset controller counters
        """
        self.start_time = time.time()
        self.packet_in_count = 0
        self.packet_in_events.clear()
        self.attack_detected = False
        self.mitigation_start_time = None
        self.last_detection_time = None

        # reset mitigation stats
        self.mitigated_drop_count = 0
        self.mitigated_sources.clear()

        # reset source rate tracking
        self.source_packet_counts.clear()
        self.source_last_reset = time.time()

        # reset drop counters of unknown and over-rate sources
        self.dropped_unknown_count = 0
        self.dropped_overrate_count = 0

        self.source_seen_counts.clear()
        self.trusted_sources.clear()
    
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
        return self.mitigation_start_time

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
            "mitigated_sources": dict(self.mitigated_sources),
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
        if buffer_id is not None:
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
    
    def update_source_rate(self, src):
        now = time.time()

        # reset every WINDOW_SECONDS
        if now - self.source_last_reset > WINDOW_SECONDS:
            self.source_packet_counts.clear()
            self.source_last_reset = now

        self.source_packet_counts[src] += 1

    def update_packet_in_stats(self):
        self.packet_in_count += 1 # "packet in" count increase
        self.packet_in_events.append(time.time())   # update event list with this event's timestamp
        self._update_attack_status()

    # drop unknown sources during attack mode
    def should_drop_packet(self, src, dpid, in_port, source_known, source_trusted):
        # logic to auto-drop packets from unknown sources during attack mode
        if self.attack_detected and not source_trusted:
            self.mitigated_drop_count += 1
            self.dropped_unknown_count += 1
            self.mitigated_sources[src] += 1
            self.logger.warning(
                "Mitigation: dropping unknown source %s on switch=%s port=%s during attack mode",
                src, dpid, in_port
            )
            return True

        
        """ 
        logic to drop packets from known sources that exceed a certain delivery rate during attack mode
            - I wanted to set up a white listing function for the project, but given the spoofing circumstances 
              or possible penetration attacks, known sources are not fully trustworthy. 
              Therefore, I set up a rate threshold for known sources as well, which is a more flexible and safer approach.
        """
        if self.attack_detected and source_known:
            if self.source_packet_counts[src] > self.source_rate_threshold:
                self.mitigated_drop_count += 1
                self.dropped_overrate_count += 1
                self.mitigated_sources[src] += 1
                self.logger.warning(
                    "Mitigation: dropping OVER-RATE source %s on switch=%s port=%s",
                    src, dpid, in_port
                )
                return True

        return False
    
    def parse_packet_content(self, msg):
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ipv4_pkt.src if ipv4_pkt else None

        return {
            "datapath": datapath,
            "dpid": dpid,
            "ofproto": ofproto,
            "parser": parser,
            "in_port": in_port,
            "pkt": pkt,
            "eth": eth,
            "src": eth.src,
            "dst": eth.dst,
            "src_ip": src_ip,
        }
    
    def learn_host(self, src, src_ip, dpid, in_port):
        # Record host location
        self.hosts[src] = {
            "ip": src_ip,
            "dpid": dpid,
            "port": in_port,
            "last_seen": time.time()
        }                

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

    def update_source_trust(self, src):
        # only build trust outside attack mode
        if self.attack_detected:
            return

        self.source_seen_counts[src] += 1

        if self.source_seen_counts[src] >= self.trust_threshold:
            self.trusted_sources.add(src)

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

        msg = ev.msg

        # PI stats
        self.update_packet_in_stats()

        # parse packet + context
        ctx = self.parse_packet_content(msg)

        datapath = ctx["datapath"]
        dpid = ctx["dpid"]
        ofproto = ctx["ofproto"]
        parser = ctx["parser"]
        in_port = ctx["in_port"]
        eth = ctx["eth"]
        src = ctx["src"]
        dst = ctx["dst"]
        src_ip = ctx["src_ip"]

        # ignore LLDP packets used for topology discovery
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # checking if the source is already known
        source_known = src in self.hosts
        self.update_source_rate(src)

        self.update_source_trust(src)
        source_trusted = src in self.trusted_sources

        # mitigation: drop unknown sources during attack mode
        if self.should_drop_packet(src, dpid, in_port, source_known, source_trusted):
            return

        # Record host location
        self.learn_host(src, src_ip, dpid, in_port)

        self.logger.info(
            "Packet in: switch=%s src=%s dst=%s in_port=%s",
            dpid, src, dst, in_port
        )

        # if destination MAC is known, send to that port, otherwise flood
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a forwarding rule for learned hosts to avoid future controller hops
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst,
                eth_src=src
            )

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

    def get_mitigation_summary(self):
        return {
            "mitigated_drop_count": self.mitigated_drop_count,
            "dropped_unknown_count": self.dropped_unknown_count,
            "dropped_overrate_count": self.dropped_overrate_count,
            "mitigated_sources": dict(self.mitigated_sources),
            "source_rate_threshold": self.source_rate_threshold,
            "source_packet_counts": dict(self.source_packet_counts),
            "trust_threshold": self.trust_threshold,
            "trusted_sources": list(self.trusted_sources),
            "source_seen_counts": dict(self.source_seen_counts),
        }

