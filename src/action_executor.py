#!/usr/bin/env python3
"""
Action Executor - Real-world action implementation for autonomous agent
Transforms simulated actions into actual network security responses
"""

import subprocess
import platform
import os
import logging
import time
import json
import smtplib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import threading

# Prefer shared safety controls module if available
try:
    from src.safety_controls import SafetyControls  # type: ignore
except ImportError:
    try:
        from safety_controls import SafetyControls  # type: ignore
    except ImportError:
        SafetyControls = None  # Fallback to internal definition below

class ActionResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLBACK = "rollback"

@dataclass
class ExecutedAction:
    action_id: str
    action_type: str
    target: str
    timestamp: datetime
    result: ActionResult
    details: str
    rollback_command: Optional[str] = None
    expires_at: Optional[datetime] = None

if SafetyControls is None:
    class SafetyControls:  # type: ignore
        """Safety controls to prevent destructive actions (fallback)."""

        def __init__(self, config: Dict[str, Any] = None):
            self.config = config or {}
            self.ip_whitelist = set(self.config.get('ip_whitelist', ['127.0.0.1', '::1']))
            self.max_blocks_per_hour = self.config.get('max_blocks_per_hour', 10)
            self.max_alerts_per_hour = self.config.get('max_alerts_per_hour', 50)
            self.recent_actions = []

        def is_ip_safe_to_block(self, ip: str) -> bool:
            return ip not in self.ip_whitelist

        def can_take_action(self, action_type: str) -> bool:
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
            self.recent_actions.append({'type': action_type, 'target': target, 'timestamp': datetime.now()})

class ActionExecutor:
    """Executes real-world security actions"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.safety = SafetyControls(config.get('safety', {}))

        # Track executed actions for rollback
        self.executed_actions: List[ExecutedAction] = []

        # Execution modes
        self.dry_run = config.get('dry_run', False)
        self.enable_ip_blocking = config.get('enable_ip_blocking', False)
        self.enable_notifications = config.get('enable_notifications', True)

        # Notification settings
        self.webhook_url = config.get('webhook_url')
        self.email_config = config.get('email_config', {})

        self.logger.info(f"ActionExecutor initialized - dry_run: {self.dry_run}")

    def execute_block_ip(self, ip: str, reason: str) -> ExecutedAction:
        """Block an IP address using system firewall"""
        action_id = f"block_{ip}_{int(time.time())}"

        # Safety checks
        if not self.safety.is_ip_safe_to_block(ip):
            return ExecutedAction(
                action_id=action_id,
                action_type="block_ip",
                target=ip,
                timestamp=datetime.now(),
                result=ActionResult.SKIPPED,
                details=f"IP {ip} is in whitelist - blocking skipped for safety"
            )

        if not self.safety.can_take_action('block_ip'):
            return ExecutedAction(
                action_id=action_id,
                action_type="block_ip",
                target=ip,
                timestamp=datetime.now(),
                result=ActionResult.SKIPPED,
                details="Rate limit exceeded - too many recent blocks"
            )

        if self.dry_run or not self.enable_ip_blocking:
            self.logger.warning(f"🧪 DRY RUN: Would block IP {ip} - {reason}")
            return ExecutedAction(
                action_id=action_id,
                action_type="block_ip",
                target=ip,
                timestamp=datetime.now(),
                result=ActionResult.SKIPPED,
                details=f"Dry run mode - would block {ip}"
            )

        try:
            # Determine the appropriate firewall command based on OS
            rollback_command = None

            if platform.system() == "Linux":
                # Use iptables
                block_command = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                rollback_command = f"iptables -D INPUT -s {ip} -j DROP"

            elif platform.system() == "Darwin":  # macOS
                # Use pfctl
                block_command = ["pfctl", "-t", "blocked_ips", "-T", "add", ip]
                rollback_command = f"pfctl -t blocked_ips -T delete {ip}"

            elif platform.system() == "Windows":
                # Use Windows Firewall
                block_command = ["netsh", "advfirewall", "firewall", "add", "rule",
                               f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
                rollback_command = f"netsh advfirewall firewall delete rule name=Block_{ip}"

            else:
                raise Exception(f"Unsupported operating system: {platform.system()}")

            # Execute the command
            result = subprocess.run(block_command, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self.safety.record_action('block_ip', ip)

                executed_action = ExecutedAction(
                    action_id=action_id,
                    action_type="block_ip",
                    target=ip,
                    timestamp=datetime.now(),
                    result=ActionResult.SUCCESS,
                    details=f"Successfully blocked {ip} using {' '.join(block_command)}",
                    rollback_command=rollback_command,
                    expires_at=datetime.now() + timedelta(hours=24)  # Auto-expire in 24 hours
                )

                self.executed_actions.append(executed_action)
                self.logger.warning(f"🚫 BLOCKED IP: {ip} - {reason}")

                # Schedule auto-rollback
                self._schedule_auto_rollback(executed_action)

                return executed_action

            else:
                return ExecutedAction(
                    action_id=action_id,
                    action_type="block_ip",
                    target=ip,
                    timestamp=datetime.now(),
                    result=ActionResult.FAILED,
                    details=f"Command failed: {result.stderr}"
                )

        except Exception as e:
            self.logger.error(f"Failed to block IP {ip}: {e}")
            return ExecutedAction(
                action_id=action_id,
                action_type="block_ip",
                target=ip,
                timestamp=datetime.now(),
                result=ActionResult.FAILED,
                details=f"Exception: {str(e)}"
            )

    def execute_send_alert(self, reason: str, confidence: float, target: str = "network") -> ExecutedAction:
        """Send security alert via configured channels"""
        action_id = f"alert_{int(time.time())}"

        if not self.safety.can_take_action('alert'):
            return ExecutedAction(
                action_id=action_id,
                action_type="alert",
                target=target,
                timestamp=datetime.now(),
                result=ActionResult.SKIPPED,
                details="Rate limit exceeded - too many recent alerts"
            )

        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'confidence': confidence,
            'target': target,
            'severity': 'HIGH' if confidence > 0.7 else 'MEDIUM' if confidence > 0.4 else 'LOW'
        }

        success_channels = []
        failed_channels = []

        # Log alert
        self.logger.warning(f"🚨 SECURITY ALERT: {reason} (confidence: {confidence:.2f})")
        success_channels.append("logs")

        # Send webhook notification
        if self.webhook_url and self.enable_notifications:
            try:
                response = requests.post(
                    self.webhook_url,
                    json=alert_data,
                    timeout=10,
                    headers={'Content-Type': 'application/json'}
                )
                if response.status_code == 200:
                    success_channels.append("webhook")
                else:
                    failed_channels.append(f"webhook (status: {response.status_code})")
            except Exception as e:
                failed_channels.append(f"webhook (error: {str(e)})")

        # Send email notification
        if self.email_config and self.enable_notifications:
            try:
                self._send_email_alert(alert_data)
                success_channels.append("email")
            except Exception as e:
                failed_channels.append(f"email (error: {str(e)})")

        # Write to alert file
        try:
            alert_file = self.config.get('alert_file', 'security_alerts.log')
            with open(alert_file, 'a') as f:
                f.write(f"{json.dumps(alert_data)}\n")
            success_channels.append("file")
        except Exception as e:
            failed_channels.append(f"file (error: {str(e)})")

        self.safety.record_action('alert', target)

        return ExecutedAction(
            action_id=action_id,
            action_type="alert",
            target=target,
            timestamp=datetime.now(),
            result=ActionResult.SUCCESS if success_channels else ActionResult.FAILED,
            details=f"Alert sent via: {', '.join(success_channels)}. Failed: {', '.join(failed_channels) if failed_channels else 'none'}"
        )

    def execute_start_investigation(self, target: str, reason: str) -> ExecutedAction:
        """Start deeper investigation of a target"""
        action_id = f"investigate_{target}_{int(time.time())}"

        investigation_data = {
            'target': target,
            'reason': reason,
            'timestamp': datetime.now().isoformat(),
            'actions': []
        }

        try:
            # Enhanced logging for target
            investigation_data['actions'].append("enhanced_logging")

            # Create investigation directory
            investigation_dir = f"investigations/{target}_{int(time.time())}"
            os.makedirs(investigation_dir, exist_ok=True)
            investigation_data['actions'].append(f"created_directory:{investigation_dir}")

            # Log investigation start
            with open(f"{investigation_dir}/investigation.json", 'w') as f:
                json.dump(investigation_data, f, indent=2)

            self.logger.info(f"🔍 INVESTIGATION STARTED: {target} - {reason}")

            return ExecutedAction(
                action_id=action_id,
                action_type="investigate",
                target=target,
                timestamp=datetime.now(),
                result=ActionResult.SUCCESS,
                details=f"Investigation started in {investigation_dir}"
            )

        except Exception as e:
            return ExecutedAction(
                action_id=action_id,
                action_type="investigate",
                target=target,
                timestamp=datetime.now(),
                result=ActionResult.FAILED,
                details=f"Failed to start investigation: {str(e)}"
            )

    def execute_escalate_to_human(self, reason: str, confidence: float) -> ExecutedAction:
        """Escalate critical threats to human analysts"""
        action_id = f"escalate_{int(time.time())}"

        escalation_data = {
            'timestamp': datetime.now().isoformat(),
            'reason': reason,
            'confidence': confidence,
            'severity': 'CRITICAL',
            'requires_human_action': True
        }

        success_actions = []

        try:
            # Log critical escalation
            self.logger.critical(f"🆘 CRITICAL ESCALATION: {reason} (confidence: {confidence:.2f})")
            success_actions.append("logged")

            # Send high-priority alert
            if self.webhook_url:
                try:
                    response = requests.post(
                        f"{self.webhook_url}/critical",
                        json=escalation_data,
                        timeout=10
                    )
                    if response.status_code == 200:
                        success_actions.append("webhook_critical")
                except:
                    pass

            # Write to critical alerts file
            critical_file = self.config.get('critical_alert_file', 'critical_alerts.log')
            with open(critical_file, 'a') as f:
                f.write(f"{json.dumps(escalation_data)}\n")
            success_actions.append("critical_file")

            # Send email to security team if configured
            if self.email_config.get('security_team_email'):
                try:
                    self._send_critical_email(escalation_data)
                    success_actions.append("security_team_email")
                except:
                    pass

            return ExecutedAction(
                action_id=action_id,
                action_type="escalate",
                target="security_team",
                timestamp=datetime.now(),
                result=ActionResult.SUCCESS,
                details=f"Escalated via: {', '.join(success_actions)}"
            )

        except Exception as e:
            return ExecutedAction(
                action_id=action_id,
                action_type="escalate",
                target="security_team",
                timestamp=datetime.now(),
                result=ActionResult.FAILED,
                details=f"Escalation failed: {str(e)}"
            )

    def rollback_action(self, action_id: str) -> bool:
        """Rollback a previously executed action"""
        action = next((a for a in self.executed_actions if a.action_id == action_id), None)

        if not action:
            self.logger.error(f"Action {action_id} not found for rollback")
            return False

        if not action.rollback_command:
            self.logger.warning(f"No rollback command for action {action_id}")
            return False

        try:
            if action.action_type == "block_ip":
                # Execute rollback command
                result = subprocess.run(
                    action.rollback_command.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    self.logger.info(f"✅ Rolled back action {action_id}: {action.rollback_command}")
                    action.result = ActionResult.ROLLBACK
                    return True
                else:
                    self.logger.error(f"Rollback failed for {action_id}: {result.stderr}")
                    return False

        except Exception as e:
            self.logger.error(f"Exception during rollback of {action_id}: {e}")
            return False

        return False

    def _schedule_auto_rollback(self, action: ExecutedAction):
        """Schedule automatic rollback of temporary actions"""
        if not action.expires_at:
            return

        def rollback_timer():
            sleep_time = (action.expires_at - datetime.now()).total_seconds()
            if sleep_time > 0:
                time.sleep(sleep_time)
                self.rollback_action(action.action_id)

        rollback_thread = threading.Thread(target=rollback_timer, daemon=True)
        rollback_thread.start()

    def _send_email_alert(self, alert_data: Dict[str, Any]):
        """Send email alert"""
        if not self.email_config:
            return

        smtp_server = self.email_config.get('smtp_server')
        smtp_port = self.email_config.get('smtp_port', 587)
        username = self.email_config.get('username')
        password = self.email_config.get('password')
        to_email = self.email_config.get('alert_email')

        if not all([smtp_server, username, password, to_email]):
            return

        subject = f"PacketSense Security Alert - {alert_data['severity']}"
        body = f"""
Security Alert Detected:

Timestamp: {alert_data['timestamp']}
Reason: {alert_data['reason']}
Confidence: {alert_data['confidence']}
Target: {alert_data['target']}
Severity: {alert_data['severity']}

This is an automated alert from PacketSense AI.
        """

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)

        message = f"Subject: {subject}\n\n{body}"
        server.sendmail(username, to_email, message)
        server.quit()

    def _send_critical_email(self, escalation_data: Dict[str, Any]):
        """Send critical escalation email"""
        if not self.email_config:
            return

        security_email = self.email_config.get('security_team_email')
        if not security_email:
            return

        # Use same SMTP config but different recipient
        temp_config = self.email_config.copy()
        temp_config['alert_email'] = security_email

        alert_data = escalation_data.copy()
        alert_data['severity'] = 'CRITICAL'

        old_config = self.email_config
        self.email_config = temp_config
        try:
            self._send_email_alert(alert_data)
        finally:
            self.email_config = old_config

    def get_execution_stats(self) -> Dict[str, Any]:
        """Get statistics about executed actions"""
        total_actions = len(self.executed_actions)
        successful_actions = len([a for a in self.executed_actions if a.result == ActionResult.SUCCESS])
        failed_actions = len([a for a in self.executed_actions if a.result == ActionResult.FAILED])
        skipped_actions = len([a for a in self.executed_actions if a.result == ActionResult.SKIPPED])

        return {
            'total_actions': total_actions,
            'successful_actions': successful_actions,
            'failed_actions': failed_actions,
            'skipped_actions': skipped_actions,
            'success_rate': successful_actions / total_actions if total_actions > 0 else 0,
            'recent_actions': [
                {
                    'id': a.action_id,
                    'type': a.action_type,
                    'target': a.target,
                    'result': a.result.value,
                    'timestamp': a.timestamp.isoformat()
                } for a in self.executed_actions[-10:]  # Last 10 actions
            ]
        }
