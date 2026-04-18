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
        #print("DEBUG: app object id in /stats =", id(self.app))
        #print("DEBUG: packet_in_count in /stats =", self.app.packet_in_count)
        body = json.dumps(self.app.get_stats(), indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )
        
    @route('switches', "/switches", methods=['GET'])
    def switches(self, req, **kwargs):
        """_
        GET  /switches

        Returns a list of switches connected to the controller
        """
        body = json.dumps(self.app.get_switches(), indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )
    
    @route('hosts', "/hosts", methods=['GET'])
    def hosts(self, req, **kwargs):
        """_
        GET  /hosts

        Returns a list of hosts learned by the controller
        """
        body = json.dumps(self.app.get_hosts(), indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )
    
    @route('flows', "/flows", methods=['GET'])
    def flows(self, req, **kwargs):
        """_
        GET  /flows

        Returns a summary of learned forwarding rules
        """
        body = json.dumps(self.app.get_flows_summary(), indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )
        
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
            "attack detected": self.app.attack_detected,
            "packet_in_rate": round(self.app._packet_in_rate(WINDOW_SECONDS), 2),
            "threshold_rate": self.app.packet_in_threshold,
            "attack_detection_time": self.app.last_detection_time
        }
        body = json.dumps(data, indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )
        
    @route('attack_metrics', "/attack/metrics", methods=['GET'])
    def attack_metrics(self, req, **kwargs):
        """
        GET /attack/metrics
        
        Return metrics related to attack detection such as:
            - hosts involved
            - suspicious flows
            - recent Packet-In history
        """
        pass
    
    @route('mitigate_start', "/mitigate/start", methods=['POST'])
    def mitigate_start(self, req, **kwargs):
        """
        POST /mitigate/start
        
        Simulate the start of the mitigation strategy
        """
        
        # note mitigation start time
        mitigation_time_start = self.app._note_mitigation_start()
        
        # TODO: mitigation logic
    
    @route('mitigate_end', "/mitigate/end", methods=['POST'])
    def mitigate_end(self, req, **kwargs):
        """
        POST /mitigate/end
        
        """
        pass

    @route('reset', "/config/reset", methods=['POST'])
    def reset(self, req, **kwargs):
        """ TODO: DOES NOT WORK
        GET  /config/reset

        Resets PI counters and states
        """
        self.app.reset_counters()
        
        message = {
            "result": "success",
            "message": "counters and states reset"
        }
        body = json.dumps(message, indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )    
    
    @route('update_threshold', "/config/threshold", methods=['POST'])
    def update_threshold(self, req, **kwargs):
        """
        POST /config/threshold

        Update the Packet-In threshold for attack detection
        """
        try:
            data = req.json_body
            new_threshold = int(data.get("threshold", self.app.packet_in_threshold))
            self.app.packet_in_threshold = new_threshold
            
            message = {
                "result": "success",
                "message": f"Packet-In threshold updated to {new_threshold}"
            }
        except Exception as e:
            message = {
                "result": "error",
                "message": f"Failed to update threshold: {str(e)}"
            }
        
        body = json.dumps(message, indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )

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
        body = json.dumps(data, indent=2) + "\n"
        return Response(
            content_type='application/json',
            text=body
        )