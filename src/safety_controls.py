#!/usr/bin/env python3
"""
Safety Controls module
Centralizes guardrails for destructive actions (whitelists, rate limits, override hooks).
"""

from datetime import datetime, timedelta
from typing import Dict, Any

class SafetyControls:
    """Safety controls to prevent destructive agent actions."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

        # Whitelisted IPs that must never be blocked
        self.ip_whitelist = set(self.config.get('ip_whitelist', [
            '127.0.0.1', '::1', '192.168.1.1', '10.0.0.1', '172.16.0.1'
        ]))

        # Action rate limits per hour
        self.max_blocks_per_hour = int(self.config.get('max_blocks_per_hour', 10))
        self.max_alerts_per_hour = int(self.config.get('max_alerts_per_hour', 50))

        # Optional human override flag
        self.human_override = bool(self.config.get('human_override', False))

        # Track recent actions (type, target, timestamp)
        self.recent_actions = []

    def is_ip_safe_to_block(self, ip: str) -> bool:
        """Check if an IP is safe to block based on whitelist and override."""
        if self.human_override:
            return False
        return ip not in self.ip_whitelist

    def can_take_action(self, action_type: str) -> bool:
        """Enforce per-hour rate limits for actions."""
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        self.recent_actions = [a for a in self.recent_actions if a['timestamp'] > hour_ago]

        recent_count = len([a for a in self.recent_actions if a['type'] == action_type])
        if action_type == 'block_ip' and recent_count >= self.max_blocks_per_hour:
            return False
        if action_type == 'alert' and recent_count >= self.max_alerts_per_hour:
            return False
        return True

    def record_action(self, action_type: str, target: str):
        """Record an action for rate limiting and auditing."""
        self.recent_actions.append({'type': action_type, 'target': target, 'timestamp': datetime.now()})

