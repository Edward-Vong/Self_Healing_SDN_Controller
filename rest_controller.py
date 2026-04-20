import json 
import time

from ryu.app.wsgi import ControllerBase, route
from webob import Response

from config import INSTANCE_NAME, WINDOW_SECONDS

class RestController(ControllerBase):
    """
    REST controller that exposes the custom API routes.

    REST routes implemented:
    - GET  /stats               - controller stats
    - GET  /switches            - list of connected switches
    - GET  /hosts               - list of learned hosts
    - GET  /flows               - summary of learned flows
    - GET  /attack/status       - return attack detection status and related metrics
    - GET  /attack/metrics      - return attack metrics
    - POST /mitigate/start      - start the mitigation
    - POST /mitigate/end        - end the mitigation
    - POST /config/reset        - reset controller counters and states
    - POST /config/threshold    - update the Packet-In threshold
    - GET  /history             - return recent Packet-In event history
    """

    def __init__(self, req, link, data, **config):
        super(RestController, self).__init__(req, link, data, **config)
        self.app = data[INSTANCE_NAME]

    def _json_response(self, data, status=200):
        """Helper to create a JSON response."""
        return Response(
            content_type='application/json',
            text=json.dumps(data, indent=2) + "\n",
            status=status
        )

    def _parse_json_body(self, req):
        """Helper to parse JSON body from request."""
        try:
            return req.json_body
        except Exception:
            return None

    @route('stats', '/stats', methods=['GET'])
    def stats(self, req, **kwargs):
        """
        GET /stats

        Returns controller stats:
        - total Packet-In events
        - controller uptime
        - number of connected switches and hosts
        - Packet_In total and rate
        - total flows learned
        - attack status
        - Packet_In threshold
        """
        body = json.dumps(self.app.get_stats(), indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )
        
    @route('switches', "/switches", methods=['GET'])
    def switches(self, req, **kwargs):
        """
        GET  /switches

        Returns a list of switches connected to the controller
        """
        return self._json_response(self.app.get_switches())
    
    @route('hosts', "/hosts", methods=['GET'])
    def hosts(self, req, **kwargs):
        """
        GET  /hosts

        Returns a list of hosts learned by the controller
        """
        return self._json_response(self.app.get_hosts())
    
    @route('flows', "/flows", methods=['GET'])
    def flows(self, req, **kwargs):
        """
        GET  /flows

        Returns a summary of learned forwarding rules
        """
        return self._json_response(self.app.get_flows_summary())
        
    @route('attack_status', "/attack/status", methods=['GET'])
    def attack_status(self, req, **kwargs):
        """ 
        GET  /attack/status

        Returns controller attack detection status and related metrics such as:
            - attack detected (T/F)
            - current Packet-In-rate
            - Packet-In threshold
            - last attack detection time
        """
        self.app._update_attack_status()
        
        data = {
            "attack_detected": self.app.attack_detected,
            "manual_mitigation": self.app.manual_mitigation,
            "packet_in_rate": round(self.app._packet_in_rate(WINDOW_SECONDS), 2),
            "threshold_rate": self.app.packet_in_threshold,
            "attack_detection_time": self.app.last_detection_time,
            "mitigation_start_time": self.app.mitigation_start_time
        }
        return self._json_response(data)
        
    @route('attack_metrics', "/attack/metrics", methods=['GET'])
    def attack_metrics(self, req, **kwargs):
        """
        GET /attack/metrics
        
        Return metrics related to attack detection such as:
            - hosts involved
            - suspicious flows
            - recent Packet-In history
        """
        data = {
            "attack_detected": self.app.attack_detected,
            "packet_in_rate": round(self.app._packet_in_rate(WINDOW_SECONDS), 2),
            "packet_in_threshold": self.app.packet_in_threshold,
            "mitigation": self.app.get_mitigation_summary()
        }

        return self._json_response(data)
    
    @route('mitigate_start', "/mitigate/start", methods=['POST'])
    def mitigate_start(self, req, **kwargs):
        """
        POST /mitigate/start
        
        Manually start mitigation mode
        """
        data = self.app.start_mitigation()
        return self._json_response(data)
    
    @route('mitigate_end', "/mitigate/end", methods=['POST'])
    def mitigate_end(self, req, **kwargs):
        """
        POST /mitigate/end

        Manually end mitigation mode
        """
        return self._json_response(self.app.end_mitigation())

    @route('reset', "/config/reset", methods=['POST'])
    def reset(self, req, **kwargs):
        """ 
        GET  /config/reset

        Resets PI counters and states
        """
        self.app.reset_counters()
        
        message = {
            "result": "success",
            "message": "counters and states reset"
        }
        return self._json_response(message)
    
    @route('update_threshold', "/config/threshold", methods=['POST'])
    def update_threshold(self, req, **kwargs):
        """
        POST /config/threshold

        Update the Packet-In threshold for attack detection
        """
        data = self._parse_json_body(req)
        if data is None:
            message = {
                "result": "error",
                "message": "Invalid JSON in request body"
            }
            return self._json_response(message, 400)
        
        new_threshold = int(data.get("threshold", self.app.packet_in_threshold))
        self.app.packet_in_threshold = new_threshold
        
        message = {
            "result": "success",
            "message": f"Packet-In threshold updated to {new_threshold}"
        }
        return self._json_response(message)
    
    @route('history', "/history", methods=['GET'])
    def history(self, req, **kwarsg):
        """
        GET /history
        
        Return (in timestamps):
            - recent Packet-In event history
            - mitigation start time
            - attack detection timestamp
        """
        data = {
            "packet_in_events": list(self.app.packet_in_events),
            "mitigation_start_time": self.app.mitigation_start_time,
            "last_detection_time": self.app.last_detection_time
        }
        return self._json_response(data)
    