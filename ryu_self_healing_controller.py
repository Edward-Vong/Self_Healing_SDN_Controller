import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication

from config import (
    INSTANCE_NAME,
    WINDOW_SECONDS,
    PACKET_IN_THRESHOLD,
    CONTROLLER_NAME,
    SOURCE_RATE_THRESHOLD,
    TRUST_THRESHOLD,
    MITIGATION_ENABLED,
    LEARNING_PRIORITY,
    ATTACK_METER_RATE,
    ESCALATION_THRESHOLD_SECONDS,
    HOLDDOWN_WINDOWS,
    MITIGATION_MIN_ACTIVE_WINDOWS,
    RECOVERY_QUIET_WINDOWS,
)

from rest_controller import RestController
from attack_state import AttackState
from mitigation_manager import MitigationManager
from recovery_manager import RecoveryManager

class SelfHealingSDNController(app_manager.RyuApp):
    """OpenFlow 1.3 learning switch with trust-aware mitigation controls."""
    #print("debugging: in ryu app\n")
    # Use OpenFlow 1.3 for this controller
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    # ------------------------------------------------------------------
    # Lifecycle / Initialization
    # ------------------------------------------------------------------

    def __init__(self, *args, **kwargs):
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
        self.start_time = time.time()
        self.packet_in_count = 0
        self.packet_in_events = deque()

        # Controller CPU sampling state
        self._cpu_last_wall = time.time()
        self._cpu_last_proc = time.process_time()
        self._cpu_percent = 0.0
        
        # Attack detection
        self.packet_in_threshold = PACKET_IN_THRESHOLD
        self.attack_detected = False
        self.last_detection_time = None
        self.attack_clear_time = None  # When rate first dropped below threshold
        self.recovery_eligible_time = None  # Earliest time recovery may begin after quiet period
        self.mitigation_latch_until = 0.0  # Keep mitigation engaged briefly after detection/clear
        self.mitigation_min_active_seconds = max(1.0, MITIGATION_MIN_ACTIVE_WINDOWS * WINDOW_SECONDS)
        self.recovery_quiet_seconds = max(1.0, RECOVERY_QUIET_WINDOWS * WINDOW_SECONDS)
        self._last_status_update = 0.0

        # Mitigation state
        self.mitigation_enabled = MITIGATION_ENABLED
        self.manual_mitigation = False
        self.mitigation_start_time = None

        # Source tracking for trust
        self.source_packet_counts = defaultdict(int)
        self.source_last_reset = time.time()
        self.source_rate_threshold = SOURCE_RATE_THRESHOLD
        self.source_seen_counts = defaultdict(int)
        self.trusted_sources = set()
        self.trust_threshold = TRUST_THRESHOLD
        self.mitigated_sources = defaultdict(int)  # Track mitigated packet count per source

        # Initialize managers
        self.attack_state = AttackState(self.logger)
        self.mitigation_manager = MitigationManager(self.attack_state, self.logger, meter_rate=ATTACK_METER_RATE)
        self.recovery_manager = RecoveryManager(self.attack_state, self.mitigation_manager, self.logger)

        self.logger.info("self healing sdn api app started")

    def reset_counters(self):
        """Reset runtime counters and transient mitigation/trust state."""
        self.start_time = time.time()
        self.packet_in_count = 0
        self.packet_in_events.clear()
        self.attack_detected = False
        self.last_detection_time = None
        self.attack_clear_time = None
        self.recovery_eligible_time = None
        self.mitigation_latch_until = 0.0
        self._last_status_update = 0.0
        self.manual_mitigation = False

        # reset source rate tracking
        self.source_packet_counts.clear()
        self.source_last_reset = time.time()

        # reset trust evaluation stats
        self.source_seen_counts.clear()
        self.trusted_sources.clear()

        # reset managers
        self.attack_state.clear_all()
        self.recovery_manager.reset()

    # ------------------------------------------------------------------
    # Stats / Monitoring
    # ------------------------------------------------------------------

    def get_mitigation_summary(self):
        """Return a compact snapshot of mitigation, trust, and recovery state."""
        rate_limited = {}
        escalated = {}
        for dpid in self.datapaths.keys():
            rate_limited[dpid] = list(self.attack_state.get_rate_limited_ports(dpid))
            escalated[dpid] = [
                port for port in self.attack_state.get_rate_limited_ports(dpid) 
                if self.attack_state.is_escalated(dpid, port)
            ]
        
        return {
            "mitigation_enabled": self.mitigation_enabled,
            "mitigation_active": self.mitigation_active(),
            "manual_mitigation": self.manual_mitigation,
            "recovery_mode": self.recovery_manager.is_recovering(),
            "recovery_progress": round(self.recovery_manager.get_progress(), 2),
            "rate_limited_ports": rate_limited,
            "escalated_ports": escalated,
            "source_rate_threshold": self.source_rate_threshold,
            "source_packet_counts": dict(self.source_packet_counts),
            "trust_threshold": self.trust_threshold,
            "trusted_sources": list(self.trusted_sources),
            "source_seen_counts": dict(self.source_seen_counts),
        }
    
    def _cleanup_old_packets_in_events(self, window_seconds=WINDOW_SECONDS):
        """Drop Packet-In timestamps older than the rolling window."""
        
        now = time.time()
        while self.packet_in_events and (now - self.packet_in_events[0] > window_seconds):
            self.packet_in_events.popleft()
             
    def _packet_in_rate(self, window_seconds=WINDOW_SECONDS):
        """Compute Packet-In rate for the rolling window."""
        
        self._cleanup_old_packets_in_events(window_seconds=window_seconds)
        return len(self.packet_in_events) / float(window_seconds)
    
    def _update_attack_status(self):
        """Refresh attack state, recovery progression, and escalation checks."""
        now = time.time()

        # Multiple REST endpoints can call this per polling cycle. Throttle updates
        # so status transitions are driven by traffic windows, not API call bursts.
        if now - self._last_status_update < 0.5:
            return
        self._last_status_update = now
        
        if self.manual_mitigation:
            self.attack_detected = True
            self.attack_clear_time = None
            self.recovery_eligible_time = None
            self.mitigation_latch_until = max(self.mitigation_latch_until, now + self.mitigation_min_active_seconds)
            return

        current_rate = self._packet_in_rate(window_seconds=WINDOW_SECONDS)
        was_attacked = self.attack_detected
        holddown_seconds = HOLDDOWN_WINDOWS * WINDOW_SECONDS

        if current_rate > self.packet_in_threshold:
            if not self.attack_detected:
                self.last_detection_time = now
            self.attack_detected = True
            self.attack_clear_time = None  # Reset hold-down clock while still attacking
            self.recovery_eligible_time = None
            self.mitigation_latch_until = max(self.mitigation_latch_until, now + self.mitigation_min_active_seconds)

            # If attack returns during recovery, abort recovery and keep mitigation posture.
            if self.recovery_manager.is_recovering():
                self.recovery_manager.reset()
                self.logger.info("Recovery aborted: attack rate rose above threshold again")
        else:
            if self.attack_detected:
                # Rate just dropped; start or continue the hold-down timer
                if self.attack_clear_time is None:
                    self.attack_clear_time = now
                    self.recovery_eligible_time = now + self.recovery_quiet_seconds
                    self.mitigation_latch_until = max(self.mitigation_latch_until, now + self.mitigation_min_active_seconds)
                elif now - self.attack_clear_time >= holddown_seconds:
                    self.attack_detected = False
                    self.attack_clear_time = None
                    self.mitigation_latch_until = max(self.mitigation_latch_until, now + self.mitigation_min_active_seconds)
            # If already False, nothing to do
        
        # Handle recovery transitions
        if (
            was_attacked
            and not self.attack_detected
            and not self.recovery_manager.is_recovering()
            and now >= self.mitigation_latch_until
            and self.recovery_eligible_time is not None
            and now >= self.recovery_eligible_time
        ):
            # Attack just ended, enter recovery
            self.recovery_manager.enter_recovery()
            self.recovery_eligible_time = None
        
        # Tick recovery if enabled
        if self.recovery_manager.is_recovering():
            self.recovery_manager.recovery_tick(self.datapaths)
        
        # Check escalation during active mitigation
        if self.mitigation_active():
            self.mitigation_manager.check_escalate_to_drop(
                self.datapaths, 
                escalation_threshold_sec=ESCALATION_THRESHOLD_SECONDS
            )

    def set_mitigation_enabled(self, enabled):
        """Enable or disable mitigation globally."""
        self.mitigation_enabled = bool(enabled)
        if not self.mitigation_enabled:
            self.manual_mitigation = False
            self.mitigation_start_time = None

        return {
            "result": "success",
            "mitigation_enabled": self.mitigation_enabled,
            "mitigation_active": self.mitigation_active(),
            "manual_mitigation": self.manual_mitigation,
            "attack_detected": self.attack_detected,
        }

    def _controller_cpu_percent(self):
        """Return controller process CPU usage percentage since last sample."""
        now_wall = time.time()
        now_proc = time.process_time()

        delta_wall = now_wall - self._cpu_last_wall
        delta_proc = now_proc - self._cpu_last_proc

        self._cpu_last_wall = now_wall
        self._cpu_last_proc = now_proc

        if delta_wall <= 0:
            return round(self._cpu_percent, 2)

        # Ignore ultra-short sampling windows caused by concurrent pollers.
        if delta_wall < 0.75:
            return round(self._cpu_percent, 2)

        sample = max(0.0, min(100.0, (delta_proc / delta_wall) * 100.0))
        # EWMA smoothing to reduce one-sample spikes from bursty controller load.
        self._cpu_percent = (0.7 * self._cpu_percent) + (0.3 * sample)
        return round(self._cpu_percent, 2)
            
    def get_stats(self):
        """Return top-level controller stats used by REST clients/tests."""
        
        uptime = time.time() - self.start_time
        packet_in_rate = self._packet_in_rate(window_seconds=WINDOW_SECONDS)
        controller_cpu_percent = self._controller_cpu_percent()
        self._update_attack_status()
        
        return {
            "controller": CONTROLLER_NAME,
            "uptime_seconds": round(uptime, 2),
            "connected_switches": len(self.datapaths),
            "known_hosts": len(self.hosts),
            "packet_in_total": self.packet_in_count,
            "packet_in_rate": round(packet_in_rate, 2) if uptime > 0 else 0,
            "controller_cpu_percent": controller_cpu_percent,
            "learned_mac_entries": sum(len(macs) for macs in self.mac_to_port.values()),
            "mitigation_enabled": self.mitigation_enabled,
            "mitigation_active": self.mitigation_active(),
            "attack_detected": self.attack_detected,
            "packet_in_threshold": self.packet_in_threshold,
            "manual_mitigation": self.manual_mitigation,
        }
        
    def get_switches(self):
        """Return connected switch IDs."""
        return [{"dpid": dpid} for dpid in self.datapaths.keys()]
    
    def get_hosts(self):
        """Return learned host entries."""
        return [
            {
                "mac": mac,
                "ip": info.get("ip"),
                "dpid": info.get("dpid"),
                "port": info.get("port"),
                "last_seen": round(info.get("last_seen", 0), 2)
            }
            for mac, info in self.hosts.items()
        ]

    def get_flows_summary(self):
        """Return learned forwarding intents from the MAC table view."""
        return [
            {
                "dpid": dpid,
                "match_dst_mac": mac,
                "output_port": port,
            }
            for dpid, mac_table in self.mac_to_port.items()
            for mac, port in mac_table.items()
        ]

    # ------------------------------------------------------------------
    # OpenFlow Event Handlers
    # ------------------------------------------------------------------

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
        """Install a flow entry on a switch datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": inst,
        }
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id
        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Track datapath connect/disconnect events."""
        datapath = ev.datapath
        if datapath is None:
            return

        if ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)
            self.logger.info("Switch %s disconnected", datapath.id)
        else:
            self.datapaths[datapath.id] = datapath
    
    def update_source_rate(self, src):
        """Track per-source Packet-In volume for the current time window."""
        now = time.time()

        # reset every WINDOW_SECONDS
        if now - self.source_last_reset > WINDOW_SECONDS:
            self.source_packet_counts.clear()
            self.source_last_reset = now

        self.source_packet_counts[src] += 1

    def update_packet_in_stats(self):
        """Record a Packet-In event and refresh attack status."""
        self.packet_in_count += 1 # "packet in" count increase
        self.packet_in_events.append(time.time())   # update event list with this event's timestamp
        self._update_attack_status()

    # ------------------------------------------------------------------
    # Mitigation / Trust Management
    # ------------------------------------------------------------------

    def mitigation_active(self):
        """True when mitigation is enabled and currently engaged."""
        has_metered_ports = any(
            bool(self.attack_state.get_rate_limited_ports(dpid))
            for dpid in self.datapaths.keys()
        )
        return self.mitigation_enabled and (
            self.manual_mitigation
            or self.attack_detected
            or self.recovery_manager.is_recovering()
            or time.time() < self.mitigation_latch_until
            or has_metered_ports
        )

    def _drop_overrate_source(self, src, src_ip, dpid, in_port):
        """Drop packets from trusted sources exceeding rate threshold during mitigation."""
        self.mitigated_sources[src] += 1

        # Remove compromised trusted source — it must rebuild trust from scratch
        if src in self.trusted_sources:
            self.trusted_sources.discard(src)
            self.source_seen_counts[src] = 0
            self.remove_source_flows(src)

        self.logger.warning(
            "Mitigation: dropping OVER-RATE source %s (%s) on switch=%s port=%s, trust revoked",
            src, src_ip, dpid, in_port
        )
        return True

    def should_drop_packet(self, src, source_trusted):
        """Return True when a trusted source exceeds allowed source rate."""
        return (
            self.mitigation_active()
            and source_trusted
            and self.source_packet_counts[src] > self.source_rate_threshold
        )
    
    def parse_packet_content(self, msg):
        """Extract normalized packet context used by pipeline handlers."""
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        try:
            pkt = packet.Packet(msg.data)
            eth_list = pkt.get_protocols(ethernet.ethernet)
            if not eth_list:
                return None
            eth = eth_list[0]
        except Exception as e:
            # Some malformed tunneled packets can trigger parser assertions in ryu.
            self.logger.warning("Skipping malformed packet on dpid=%s port=%s: %s", dpid, in_port, e)
            return None

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ipv4_pkt.src if ipv4_pkt else None

        return {
            "datapath": datapath,
            "dpid": dpid,
            "in_port": in_port,
            "eth": eth,
            "src": eth.src,
            "dst": eth.dst,
            "src_ip": src_ip,
        }
    
    def learn_host(self, src, src_ip, dpid, in_port):
        """Update host and MAC learning tables from source observation."""
        self.hosts[src] = {
            "ip": src_ip,
            "dpid": dpid,
            "port": in_port,
            "last_seen": time.time()
        }                

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

    def update_source_trust(self, src):
        """Increment trust evidence for a source when outside attack mode."""
        if not self.mitigation_enabled:
            return

        # only build trust outside attack mode
        if self.mitigation_active():
            return

        self.source_seen_counts[src] += 1

        if self.source_seen_counts[src] >= self.trust_threshold:
            self.trusted_sources.add(src)

    def get_trust_state(self):
        """Return trust-table state for REST inspection."""
        return {
            "trusted_sources": list(self.trusted_sources),
            "source_seen_counts": dict(self.source_seen_counts),
            "source_packet_counts": dict(self.source_packet_counts),
            "trust_threshold": self.trust_threshold,
        }

    def clear_trust_state(self):
        """Clear trust-related counters for clean test setup."""
        self.trusted_sources.clear()
        self.source_seen_counts.clear()
        self.source_packet_counts.clear()
        self.mitigated_sources.clear()
        return {
            "result": "success",
            "message": "trust state cleared",
        }

    def _send_packet_out(self, datapath, msg, in_port, actions):
        """Emit a PacketOut while preserving switch buffer usage."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _install_learning_flow(self, datapath, msg, in_port, src, dst, actions):
        """Install a learned forwarding flow; return True if buffer consumed."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, LEARNING_PRIORITY, match, actions, buffer_id=msg.buffer_id)
            return True

        self.add_flow(datapath, LEARNING_PRIORITY, match, actions)
        return False

    def _handle_mitigation_packet(self, datapath, dpid, in_port, src, src_ip, dst, msg):
        """Process a packet while mitigation is active."""
        source_trusted = src in self.trusted_sources

        if not source_trusted:
            self.attack_state.mark_attack_on_port(dpid, in_port)
            if in_port not in self.attack_state.get_rate_limited_ports(dpid):
                self.mitigation_manager.install_meter_on_port(datapath, in_port)
            self.mitigated_sources[src] += 1
            return

        if self.should_drop_packet(src, source_trusted):
            self._drop_overrate_source(src, src_ip, dpid, in_port)
            return

        # Trusted source within rate: forward only if destination is known.
        self._forward_if_known(datapath, dpid, dst, msg, in_port)

    def _handle_normal_packet(self, datapath, dpid, in_port, src, src_ip, dst, msg):
        """Process a packet under normal learning-switch behavior."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.learn_host(src, src_ip, dpid, in_port)
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            consumed = self._install_learning_flow(datapath, msg, in_port, src, dst, actions)
            if consumed:
                return

        self._send_packet_out(datapath, msg, in_port, actions)

    def _forward_if_known(self, datapath, dpid, dst, msg, in_port):
        """Forward packet only when destination is already learned."""
        parser = datapath.ofproto_parser
        if dst not in self.mac_to_port[dpid]:
            return False
        out_port = self.mac_to_port[dpid][dst]
        self._send_packet_out(datapath, msg, in_port, [parser.OFPActionOutput(out_port)])
        return True

    # ------------------------------------------------------------------
    # Mitigation Control Actions
    # ------------------------------------------------------------------

    def start_mitigation(self):
        """Force mitigation mode on through REST control."""
        if not self.mitigation_enabled:
            return {
                "result": "error",
                "message": "mitigation is disabled",
                "mitigation_enabled": self.mitigation_enabled,
            }

        self.manual_mitigation = True
        self.attack_detected = True
        self.mitigation_start_time = time.time()
        return {
            "result": "success",
            "message": "mitigation started",
            "manual_mitigation": self.manual_mitigation,
            "attack_detected": self.attack_detected,
            "mitigation_start_time": self.mitigation_start_time
        }

    def end_mitigation(self):
        """Force mitigation mode off through REST control."""
        self.manual_mitigation = False
        self.attack_detected = False
        self.mitigation_start_time = None

        return {
            "result": "success",
            "message": "mitigation ended",
            "manual_mitigation": self.manual_mitigation,
            "attack_detected": self.attack_detected,
            "mitigation_start_time": self.mitigation_start_time,
            "trusted_sources": list(self.trusted_sources),
        }
    
    def remove_source_flows(self, src):
        """Remove forwarding flows for a compromised trusted source on every switch."""
        src_ip = self.hosts.get(src, {}).get("ip")

        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            if src in self.mac_to_port[dpid]:
                del self.mac_to_port[dpid][src]

            match = parser.OFPMatch(eth_src=src)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)

        if src in self.hosts:
            del self.hosts[src]

        self.logger.warning(
            "Removed flows for compromised source %s (%s) across all %d switches",
            src, src_ip, len(self.datapaths)
        )

    # ------------------------------------------------------------------
    # Packet-In Pipeline
    # ------------------------------------------------------------------

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
        if ctx is None:
            return

        # Process the packet
        self._process_packet(ctx, msg)

    def _process_packet(self, ctx, msg):
        datapath = ctx["datapath"]
        dpid = ctx["dpid"]
        in_port = ctx["in_port"]
        eth = ctx["eth"]
        src = ctx["src"]
        dst = ctx["dst"]
        src_ip = ctx["src_ip"]

        # ignore LLDP packets used for topology discovery
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.update_source_rate(src)
        self.update_source_trust(src)

        # During attack: install meter on unknown source port or drop over-rate trusted sources
        if self.mitigation_active():
            self._handle_mitigation_packet(datapath, dpid, in_port, src, src_ip, dst, msg)
            return

        self._handle_normal_packet(datapath, dpid, in_port, src, src_ip, dst, msg)