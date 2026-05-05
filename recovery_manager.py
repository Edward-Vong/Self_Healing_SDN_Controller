"""
Recovery manager — orchestrates gradual recovery after attack subsides.
"""
import time


class RecoveryManager:
    """Manages 4-stage recovery process"""
    
    STAGE_THRESHOLDS = [0.25, 0.50, 0.75, 1.0]  # Stage transition points
    STAGE0_REMOVE_INTERVAL = 3.0  # Minimum seconds between meter removals in stage 0
    
    def __init__(self, attack_state, mitigation_manager, logger, recovery_window=60):
        self.attack_state = attack_state
        self.mitigation_manager = mitigation_manager
        self.logger = logger
        self.recovery_window = recovery_window
        self.recovery_enabled = False
        self.recovery_start_time = None
        self.current_stage = -1
        self._last_stage0_remove_time = 0.0
    
    def enter_recovery(self):
        """Start recovery phase"""
        if self.recovery_enabled:
            return  # Already in recovery
        
        self.recovery_enabled = True
        self.recovery_start_time = time.time()
        self.current_stage = 0
        self._last_stage0_remove_time = 0.0
        self.logger.info("Entering recovery phase")
    
    def recovery_tick(self, datapaths):
        """Execute one recovery step; call periodically"""
        if not self.recovery_enabled:
            return False
        
        elapsed = time.time() - self.recovery_start_time
        progress = min(1.0, elapsed / self.recovery_window)
        
        # Determine current stage
        new_stage = -1
        for i, threshold in enumerate(self.STAGE_THRESHOLDS):
            if progress < threshold:
                new_stage = i
                break
        
        # Log stage transitions
        if new_stage != self.current_stage and new_stage >= 0:
            self.current_stage = new_stage
            self.logger.info(f"Recovery stage {self.current_stage}: {int(progress * 100)}% complete")
        
        # Execute stage-specific actions
        if progress < 0.25:
            # Stage 0: Start removing meters
            self._stage_0_remove_meters(datapaths)
        elif progress < 0.50:
            # Stage 1: Re-enable learning (placeholder - controller handles)
            pass
        elif progress < 0.75:
            # Stage 2: Lower trust thresholds (placeholder - controller handles)
            pass
        else:
            # Stage 3: Full recovery
            self._stage_3_complete_recovery()
            return True  # Recovery complete
        
        return False
    
    def _stage_0_remove_meters(self, datapaths):
        """Remove meters from least-attacked ports"""
        now = time.time()
        if now - self._last_stage0_remove_time < self.STAGE0_REMOVE_INTERVAL:
            return

        for dpid, datapath in datapaths.items():
            ports_to_recover = list(self.attack_state.get_rate_limited_ports(dpid))
            if ports_to_recover:
                # Remove meter from first port in the list (one port per tick)
                port = ports_to_recover[0]
                self.mitigation_manager.remove_meter_on_port(datapath, port)
                self._last_stage0_remove_time = now
                break
    
    def _stage_3_complete_recovery(self):
        """Final cleanup for full recovery"""
        self.recovery_enabled = False
        self.recovery_start_time = None
        self.current_stage = -1
        self._last_stage0_remove_time = 0.0
        self.logger.info("Recovery complete")
    
    def is_recovering(self):
        """Check if in recovery phase"""
        return self.recovery_enabled
    
    def get_progress(self):
        """Get recovery progress (0.0 to 1.0)"""
        if not self.recovery_enabled:
            return 0.0
        elapsed = time.time() - self.recovery_start_time
        return min(1.0, elapsed / self.recovery_window)
    
    def reset(self):
        """Reset recovery state"""
        self.recovery_enabled = False
        self.recovery_start_time = None
        self.current_stage = -1
        self._last_stage0_remove_time = 0.0
