#!/usr/bin/env python3
"""
Feedback Collector - Action effectiveness tracking and learning system
Monitors action outcomes and provides feedback for agent improvement
"""

import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import json
import sqlite3
from collections import defaultdict, deque

class ActionOutcome(Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILURE = "failure"
    UNKNOWN = "unknown"

class ThreatPersistence(Enum):
    ELIMINATED = "eliminated"
    REDUCED = "reduced"
    PERSISTED = "persisted"
    ESCALATED = "escalated"

@dataclass
class ActionFeedback:
    action_id: str
    action_type: str
    target: str
    timestamp: datetime
    outcome: ActionOutcome
    threat_persistence: ThreatPersistence
    effectiveness_score: float  # 0.0 to 1.0
    response_time: float  # seconds
    side_effects: List[str]
    confidence_at_action: float
    context: Dict[str, Any]

@dataclass
class ThreatResolution:
    original_threat_id: str
    threat_level: str
    actions_taken: List[str]
    resolution_time: float
    final_outcome: ActionOutcome
    lessons_learned: List[str]

class FeedbackCollector:
    """Collects and analyzes feedback on agent actions to improve decision making"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

        # Feedback storage
        self.db_path = self.config.get('feedback_db', 'agent_feedback.db')
        self._init_database()

        # Active monitoring
        self.active_actions: Dict[str, Dict[str, Any]] = {}
        self.monitoring_threads: Dict[str, threading.Thread] = {}

        # Network state monitoring
        self.network_state_history = deque(maxlen=1000)
        self.blocked_ips: Dict[str, datetime] = {}

        # Feedback metrics
        self.feedback_metrics = {
            'total_actions_tracked': 0,
            'successful_actions': 0,
            'failed_actions': 0,
            'avg_effectiveness': 0.0,
            'avg_response_time': 0.0,
            'false_positive_rate': 0.0,
            'threat_recurrence_rate': 0.0
        }

        self.logger.info("FeedbackCollector initialized")

    # --- Public helpers for agent integration ---
    def set_blocked_ip(self, ip: str):
        """Mark an IP as currently blocked (for effectiveness analysis)."""
        try:
            self.blocked_ips[ip] = datetime.now()
        except Exception:
            pass

    def clear_blocked_ip(self, ip: str):
        """Clear an IP from blocked status (e.g., after rollback/expiry)."""
        try:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
        except Exception:
            pass

    def _init_database(self):
        """Initialize SQLite database for feedback storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Action feedback table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS action_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                outcome TEXT NOT NULL,
                threat_persistence TEXT NOT NULL,
                effectiveness_score REAL NOT NULL,
                response_time REAL NOT NULL,
                side_effects TEXT,
                confidence_at_action REAL NOT NULL,
                context TEXT
            )
        ''')

        # Threat resolution table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_resolutions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                actions_taken TEXT NOT NULL,
                resolution_time REAL NOT NULL,
                final_outcome TEXT NOT NULL,
                lessons_learned TEXT,
                timestamp TIMESTAMP NOT NULL
            )
        ''')

        # Action effectiveness patterns
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS effectiveness_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                conditions TEXT NOT NULL,
                action_type TEXT NOT NULL,
                success_rate REAL NOT NULL,
                avg_effectiveness REAL NOT NULL,
                sample_count INTEGER NOT NULL,
                last_updated TIMESTAMP NOT NULL
            )
        ''')

        conn.commit()
        conn.close()

    def start_action_monitoring(self, action_id: str, action_type: str, target: str,
                               confidence: float, threat_level: str, context: Dict[str, Any] = None):
        """Start monitoring an action for effectiveness feedback"""

        action_info = {
            'action_id': action_id,
            'action_type': action_type,
            'target': target,
            'start_time': datetime.now(),
            'confidence': confidence,
            'threat_level': threat_level,
            'context': context or {},
            'pre_action_state': self._capture_network_state(target)
        }

        self.active_actions[action_id] = action_info

        # Start monitoring thread for this action
        monitor_thread = threading.Thread(
            target=self._monitor_action_effectiveness,
            args=(action_id,),
            daemon=True
        )
        monitor_thread.start()
        self.monitoring_threads[action_id] = monitor_thread

        self.logger.debug(f"Started monitoring action {action_id} ({action_type} on {target})")

    def _monitor_action_effectiveness(self, action_id: str):
        """Monitor an action's effectiveness over time"""

        if action_id not in self.active_actions:
            return

        action_info = self.active_actions[action_id]
        target = action_info['target']
        action_type = action_info['action_type']

        # Monitoring periods
        monitoring_periods = [30, 60, 300, 900]  # 30s, 1m, 5m, 15m

        for period in monitoring_periods:
            time.sleep(period)

            if action_id not in self.active_actions:
                break  # Action monitoring was stopped

            # Capture current network state
            current_state = self._capture_network_state(target)

            # Analyze effectiveness
            effectiveness = self._analyze_action_effectiveness(
                action_info, current_state, period
            )

            # Store intermediate feedback
            self._store_intermediate_feedback(action_id, effectiveness, period)

            self.logger.debug(f"Action {action_id} effectiveness at {period}s: {effectiveness['effectiveness_score']:.2f}")

        # Final analysis after monitoring complete
        if action_id in self.active_actions:
            self._complete_action_monitoring(action_id)

    def _capture_network_state(self, target: str) -> Dict[str, Any]:
        """Capture current network state for comparison"""

        # This would integrate with live network capture in real implementation
        # For now, return simulated state
        current_time = datetime.now()

        state = {
            'timestamp': current_time,
            'target_active': True,  # Simulate target still active
            'traffic_volume': 100,  # Simulate traffic metrics
            'connection_count': 5,
            'suspicious_activity': False,
            'blocked_status': target in self.blocked_ips
        }

        # Store in history
        self.network_state_history.append({
            'target': target,
            'timestamp': current_time,
            'state': state
        })

        return state

    def _analyze_action_effectiveness(self, action_info: Dict[str, Any],
                                    current_state: Dict[str, Any],
                                    elapsed_time: int) -> Dict[str, Any]:
        """Analyze how effective an action has been"""

        action_type = action_info['action_type']
        target = action_info['target']
        pre_state = action_info['pre_action_state']

        effectiveness_score = 0.0
        threat_persistence = ThreatPersistence.UNKNOWN
        outcome = ActionOutcome.UNKNOWN
        side_effects = []

        if action_type == 'block_ip':
            # Check if IP blocking was effective
            if current_state['blocked_status']:
                # IP is blocked
                if not current_state['suspicious_activity']:
                    effectiveness_score = 0.9
                    threat_persistence = ThreatPersistence.ELIMINATED
                    outcome = ActionOutcome.SUCCESS
                else:
                    effectiveness_score = 0.3
                    threat_persistence = ThreatPersistence.PERSISTED
                    outcome = ActionOutcome.PARTIAL_SUCCESS
                    side_effects.append("Threat persisted despite blocking")
            else:
                effectiveness_score = 0.0
                outcome = ActionOutcome.FAILURE
                side_effects.append("IP blocking failed")

        elif action_type == 'alert':
            # Alerts are generally successful if sent
            effectiveness_score = 0.8
            outcome = ActionOutcome.SUCCESS
            threat_persistence = ThreatPersistence.REDUCED

        elif action_type == 'investigate':
            # Investigation effectiveness based on whether it led to resolution
            effectiveness_score = 0.6  # Baseline for investigation
            outcome = ActionOutcome.PARTIAL_SUCCESS
            threat_persistence = ThreatPersistence.REDUCED

        elif action_type == 'escalate':
            # Escalation is effective if it reaches humans
            effectiveness_score = 0.7
            outcome = ActionOutcome.SUCCESS
            threat_persistence = ThreatPersistence.REDUCED

        # Adjust effectiveness based on elapsed time
        if elapsed_time > 300:  # After 5 minutes, expect better results
            if threat_persistence == ThreatPersistence.PERSISTED:
                effectiveness_score *= 0.5  # Penalize persistent threats

        # Detect side effects
        if action_type == 'block_ip':
            # Check for potential false positive indicators
            if current_state['traffic_volume'] < pre_state['traffic_volume'] * 0.1:
                side_effects.append("Significant traffic reduction - possible false positive")
                effectiveness_score *= 0.7

        return {
            'effectiveness_score': effectiveness_score,
            'threat_persistence': threat_persistence,
            'outcome': outcome,
            'side_effects': side_effects,
            'response_time': elapsed_time
        }

    def _store_intermediate_feedback(self, action_id: str, effectiveness: Dict[str, Any], elapsed_time: int):
        """Store intermediate feedback during monitoring"""

        if action_id not in self.active_actions:
            return

        action_info = self.active_actions[action_id]

        # Update action info with latest effectiveness
        action_info[f'effectiveness_{elapsed_time}'] = effectiveness

    def _complete_action_monitoring(self, action_id: str):
        """Complete monitoring and store final feedback"""

        if action_id not in self.active_actions:
            return

        action_info = self.active_actions[action_id]

        # Calculate final effectiveness (use longest monitoring period)
        final_effectiveness = None
        for period in [900, 300, 60, 30]:  # Check in reverse order
            key = f'effectiveness_{period}'
            if key in action_info:
                final_effectiveness = action_info[key]
                break

        if not final_effectiveness:
            self.logger.warning(f"No effectiveness data for action {action_id}")
            return

        # Create feedback record
        feedback = ActionFeedback(
            action_id=action_id,
            action_type=action_info['action_type'],
            target=action_info['target'],
            timestamp=action_info['start_time'],
            outcome=final_effectiveness['outcome'],
            threat_persistence=final_effectiveness['threat_persistence'],
            effectiveness_score=final_effectiveness['effectiveness_score'],
            response_time=final_effectiveness['response_time'],
            side_effects=final_effectiveness['side_effects'],
            confidence_at_action=action_info['confidence'],
            context=action_info['context']
        )

        # Store in database
        self._store_feedback(feedback)

        # Update metrics
        self._update_feedback_metrics(feedback)

        # Learn from this feedback
        self._learn_from_feedback(feedback)

        # Clean up
        del self.active_actions[action_id]
        if action_id in self.monitoring_threads:
            del self.monitoring_threads[action_id]

        self.logger.info(f"Completed monitoring action {action_id}: {feedback.outcome.value} (score: {feedback.effectiveness_score:.2f})")

    def _store_feedback(self, feedback: ActionFeedback):
        """Store feedback in database"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO action_feedback
            (action_id, action_type, target, timestamp, outcome, threat_persistence,
             effectiveness_score, response_time, side_effects, confidence_at_action, context)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            feedback.action_id,
            feedback.action_type,
            feedback.target,
            feedback.timestamp,
            feedback.outcome.value,
            feedback.threat_persistence.value,
            feedback.effectiveness_score,
            feedback.response_time,
            json.dumps(feedback.side_effects),
            feedback.confidence_at_action,
            json.dumps(feedback.context)
        ))

        conn.commit()
        conn.close()

    def _update_feedback_metrics(self, feedback: ActionFeedback):
        """Update overall feedback metrics"""

        self.feedback_metrics['total_actions_tracked'] += 1

        if feedback.outcome in [ActionOutcome.SUCCESS, ActionOutcome.PARTIAL_SUCCESS]:
            self.feedback_metrics['successful_actions'] += 1
        else:
            self.feedback_metrics['failed_actions'] += 1

        # Update averages
        total = self.feedback_metrics['total_actions_tracked']
        old_avg_eff = self.feedback_metrics['avg_effectiveness']
        old_avg_time = self.feedback_metrics['avg_response_time']

        self.feedback_metrics['avg_effectiveness'] = (
            (old_avg_eff * (total - 1) + feedback.effectiveness_score) / total
        )

        self.feedback_metrics['avg_response_time'] = (
            (old_avg_time * (total - 1) + feedback.response_time) / total
        )

        # Calculate success rate
        success_rate = self.feedback_metrics['successful_actions'] / total
        self.feedback_metrics['false_positive_rate'] = 1.0 - success_rate

    def _learn_from_feedback(self, feedback: ActionFeedback):
        """Learn patterns from feedback to improve future decisions"""

        # Extract pattern conditions
        conditions = {
            'threat_level': feedback.context.get('threat_level', 'unknown'),
            'confidence_range': self._get_confidence_range(feedback.confidence_at_action),
            'target_type': self._classify_target_type(feedback.target),
            'time_of_day': feedback.timestamp.hour // 6  # 0-3 (night, morning, afternoon, evening)
        }

        # Store/update effectiveness pattern
        self._update_effectiveness_pattern(
            conditions, feedback.action_type, feedback.effectiveness_score
        )

    def _get_confidence_range(self, confidence: float) -> str:
        """Classify confidence into ranges"""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        elif confidence >= 0.2:
            return "low"
        else:
            return "very_low"

    def _classify_target_type(self, target: str) -> str:
        """Classify target type for pattern learning"""
        if target.startswith('192.168.') or target.startswith('10.') or target.startswith('172.'):
            return "internal_ip"
        elif '.' in target and target.replace('.', '').isdigit():
            return "external_ip"
        else:
            return "other"

    def _update_effectiveness_pattern(self, conditions: Dict[str, Any], action_type: str, effectiveness: float):
        """Update effectiveness patterns in database"""

        conditions_key = json.dumps(conditions, sort_keys=True)
        pattern_type = f"{action_type}_effectiveness"

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check if pattern exists
        cursor.execute('''
            SELECT id, success_rate, avg_effectiveness, sample_count
            FROM effectiveness_patterns
            WHERE pattern_type = ? AND conditions = ? AND action_type = ?
        ''', (pattern_type, conditions_key, action_type))

        existing = cursor.fetchone()

        if existing:
            # Update existing pattern
            pattern_id, old_success_rate, old_avg_eff, sample_count = existing
            new_sample_count = sample_count + 1
            new_avg_eff = (old_avg_eff * sample_count + effectiveness) / new_sample_count

            cursor.execute('''
                UPDATE effectiveness_patterns
                SET avg_effectiveness = ?, sample_count = ?, last_updated = ?
                WHERE id = ?
            ''', (new_avg_eff, new_sample_count, datetime.now(), pattern_id))

        else:
            # Insert new pattern
            cursor.execute('''
                INSERT INTO effectiveness_patterns
                (pattern_type, conditions, action_type, success_rate, avg_effectiveness, sample_count, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (pattern_type, conditions_key, action_type, 1.0, effectiveness, 1, datetime.now()))

        conn.commit()
        conn.close()

    def get_action_recommendation(self, action_type: str, target: str,
                                 confidence: float, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get recommendation for action based on historical effectiveness"""

        conditions = {
            'threat_level': context.get('threat_level', 'unknown') if context else 'unknown',
            'confidence_range': self._get_confidence_range(confidence),
            'target_type': self._classify_target_type(target),
            'time_of_day': datetime.now().hour // 6
        }

        conditions_key = json.dumps(conditions, sort_keys=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT avg_effectiveness, sample_count
            FROM effectiveness_patterns
            WHERE action_type = ? AND conditions = ?
        ''', (action_type, conditions_key))

        result = cursor.fetchone()
        conn.close()

        if result:
            avg_effectiveness, sample_count = result
            return {
                'recommended': avg_effectiveness > 0.6,
                'expected_effectiveness': avg_effectiveness,
                'confidence_in_prediction': min(1.0, sample_count / 10.0),
                'sample_size': sample_count,
                'conditions_matched': conditions
            }
        else:
            return {
                'recommended': True,  # Default to recommending if no data
                'expected_effectiveness': 0.5,  # Neutral expectation
                'confidence_in_prediction': 0.0,
                'sample_size': 0,
                'conditions_matched': conditions
            }

    def get_feedback_summary(self) -> Dict[str, Any]:
        """Get summary of all feedback and learning"""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get recent feedback stats
        cursor.execute('''
            SELECT action_type, AVG(effectiveness_score), COUNT(*)
            FROM action_feedback
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY action_type
        ''')

        recent_effectiveness = {row[0]: {'avg_effectiveness': row[1], 'count': row[2]}
                              for row in cursor.fetchall()}

        # Get pattern count
        cursor.execute('SELECT COUNT(*) FROM effectiveness_patterns')
        pattern_count = cursor.fetchone()[0]

        conn.close()

        return {
            'feedback_metrics': self.feedback_metrics,
            'recent_effectiveness': recent_effectiveness,
            'learned_patterns': pattern_count,
            'active_monitoring': len(self.active_actions),
            'network_state_samples': len(self.network_state_history)
        }

    def stop_action_monitoring(self, action_id: str):
        """Stop monitoring a specific action"""
        if action_id in self.active_actions:
            self._complete_action_monitoring(action_id)

    def cleanup(self):
        """Clean up resources"""
        # Complete all active monitoring
        for action_id in list(self.active_actions.keys()):
            self._complete_action_monitoring(action_id)
