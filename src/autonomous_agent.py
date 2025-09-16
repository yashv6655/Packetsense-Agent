import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import sqlite3
import json
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ActionType(Enum):
    MONITOR = "monitor"
    ALERT = "alert"
    BLOCK_IP = "block_ip"
    INVESTIGATE = "investigate"
    ESCALATE = "escalate"

@dataclass
class NetworkEvent:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    size: int
    suspicious_score: float
    event_data: Dict[str, Any]

@dataclass
class AgentAction:
    action_type: ActionType
    target: str
    reason: str
    confidence: float
    timestamp: datetime

@dataclass
class ThreatAssessment:
    threat_level: ThreatLevel
    confidence: float
    indicators: List[str]
    recommended_actions: List[ActionType]

class AgentMemory:
    """Persistent memory system for the agent to learn from past incidents"""

    def __init__(self, db_path: str = "agent_memory.db"):
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for agent memory"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create tables for different types of memory
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                indicators TEXT NOT NULL,
                threat_level INTEGER NOT NULL,
                confidence REAL NOT NULL,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                occurrence_count INTEGER DEFAULT 1
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS response_effectiveness (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_type TEXT NOT NULL,
                threat_indicators TEXT NOT NULL,
                success_rate REAL NOT NULL,
                avg_resolution_time REAL NOT NULL,
                updated_at TIMESTAMP NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                network_state TEXT NOT NULL,
                decision TEXT NOT NULL,
                outcome TEXT,
                effectiveness_score REAL
            )
        ''')

        conn.commit()
        conn.close()

    def remember_threat_pattern(self, pattern_type: str, indicators: List[str],
                              threat_level: ThreatLevel, confidence: float):
        """Store a new threat pattern or update existing one"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        indicators_json = json.dumps(indicators)
        now = datetime.now()

        # Check if pattern already exists
        cursor.execute('''
            SELECT id, occurrence_count FROM threat_patterns
            WHERE pattern_type = ? AND indicators = ?
        ''', (pattern_type, indicators_json))

        existing = cursor.fetchone()

        if existing:
            # Update existing pattern
            cursor.execute('''
                UPDATE threat_patterns
                SET last_seen = ?, occurrence_count = occurrence_count + 1,
                    confidence = (confidence + ?) / 2
                WHERE id = ?
            ''', (now, confidence, existing[0]))
        else:
            # Insert new pattern
            cursor.execute('''
                INSERT INTO threat_patterns
                (pattern_type, indicators, threat_level, confidence, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (pattern_type, indicators_json, threat_level.value, confidence, now, now))

        conn.commit()
        conn.close()

    def get_similar_patterns(self, indicators: List[str], threshold: float = 0.7) -> List[Dict]:
        """Find similar threat patterns from memory"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM threat_patterns')
        patterns = cursor.fetchall()

        similar = []
        for pattern in patterns:
            stored_indicators = json.loads(pattern[2])
            # Simple similarity calculation
            overlap = len(set(indicators) & set(stored_indicators))
            similarity = overlap / max(len(indicators), len(stored_indicators))

            if similarity >= threshold:
                similar.append({
                    'pattern_type': pattern[1],
                    'indicators': stored_indicators,
                    'threat_level': ThreatLevel(pattern[3]),
                    'confidence': pattern[4],
                    'similarity': similarity,
                    'occurrence_count': pattern[7]
                })

        conn.close()
        return sorted(similar, key=lambda x: x['similarity'], reverse=True)

class NetworkSecurityAgent:
    """Autonomous AI Network Security Agent with continuous monitoring and decision-making"""

    def __init__(self, config: Dict[str, Any] = None, network_capture=None):
        self.config = config or {}
        self.memory = AgentMemory()
        self.logger = logging.getLogger(self.__class__.__name__)

        # Store network capture reference for direct access
        self.network_capture = network_capture

        # Initialize action executor for real-world actions
        try:
            from src.action_executor import ActionExecutor
            from src.threat_detector import AIThreatDetector
            from src.feedback_collector import FeedbackCollector
        except ImportError:
            from action_executor import ActionExecutor
            from threat_detector import AIThreatDetector
            from feedback_collector import FeedbackCollector
        
        self.action_executor = ActionExecutor(self.config.get('action_executor', {}))
        self.ai_threat_detector = AIThreatDetector(self.config.get('openai_api_key'))
        self.feedback_collector = FeedbackCollector(self.config.get('feedback_collector', {}))

        # Agent state
        self.is_running = False
        self.monitoring_thread = None

        # Agent goals and metrics
        self.goals = {
            'detect_threats': 0.95,  # Target detection accuracy
            'minimize_false_positives': 0.9,  # Target specificity
            'response_time': 30.0,  # Target response time in seconds
        }

        # Performance tracking
        self.metrics = {
            'threats_detected': 0,
            'false_positives': 0,
            'actions_taken': 0,
            'avg_response_time': 0.0,
            'uptime': timedelta()
        }

        self.start_time = None
        self.last_decision_time = None

        self.logger.info("NetworkSecurityAgent initialized")

    def start_autonomous_operation(self):
        """Start the autonomous monitoring loop"""
        if self.is_running:
            self.logger.warning("Agent is already running")
            return

        self.is_running = True
        self.start_time = datetime.now()

        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()

        self.logger.info("🤖 Autonomous security agent started")

    def stop_autonomous_operation(self):
        """Stop the autonomous monitoring"""
        self.is_running = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)

        if self.start_time:
            self.metrics['uptime'] = datetime.now() - self.start_time

        self.logger.info("🛑 Autonomous security agent stopped")

    def _monitoring_loop(self):
        """Main autonomous monitoring loop - the agent's 'brain'"""
        self.logger.info("🧠 Starting autonomous monitoring loop")

        while self.is_running:
            try:
                # 1. PERCEIVE: Observe the network environment
                network_events = self._capture_network_events()

                # 2. ASSESS: Analyze threats and determine threat level
                threat_assessment = self._assess_threats(network_events)

                # 3. DECIDE: Choose what action to take
                actions = self._decide_actions(threat_assessment, network_events)

                # 4. ACT: Execute the chosen actions
                for action in actions:
                    self._execute_action(action)

                # 5. LEARN: Update knowledge based on results
                self._learn_from_experience(network_events, threat_assessment, actions)

                # 6. Update metrics and performance tracking
                self._update_performance_metrics()

                # Sleep for monitoring interval
                time.sleep(self.config.get('monitoring_interval', 5))

            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1)  # Brief pause before retrying

    def _capture_network_events(self) -> List[NetworkEvent]:
        """Capture live network events - PERCEIVE phase"""
        # This method should be overridden by the complete agent
        # If not overridden, check if we can access network capture directly
        if hasattr(self, 'network_capture') and self.network_capture:
            try:
                # Get recent events from live capture
                recent_events = self.network_capture.get_recent_events(50)

                # Convert LiveNetworkEvent to NetworkEvent format
                agent_events = []
                for event in recent_events:
                    # Calculate a basic suspicious score
                    suspicious_score = self._calculate_basic_suspicious_score(event)

                    # Create proper NetworkEvent object
                    agent_event = NetworkEvent(
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        dest_ip=event.dest_ip,
                        protocol=event.protocol,
                        size=event.size,
                        suspicious_score=suspicious_score,
                        event_data={
                            'port': event.port,
                            'raw_size': event.size
                        }
                    )
                    agent_events.append(agent_event)

                return agent_events
            except Exception as e:
                self.logger.error(f"Error capturing network events: {e}")
                return []

        # Fallback: return empty list if no network capture available
        self.logger.warning("No network capture available - agent running without live data")
        return []

    def _calculate_basic_suspicious_score(self, event) -> float:
        """Calculate a basic suspicious score for a live network event"""
        score = 0.0

        # Size-based suspicion
        if event.size > 10000:  # Large packets
            score += 0.2
        elif event.size < 60:  # Very small packets
            score += 0.1

        # Protocol-based suspicion
        if event.protocol in ['SSH', 'FTP']:
            score += 0.1  # Slightly suspicious protocols
        elif event.protocol in ['UNKNOWN', 'RAW']:
            score += 0.3  # More suspicious protocols

        # Port-based suspicion
        if hasattr(event, 'port') and event.port and event.port in [23, 135, 139, 445, 1433, 3389]:  # Known vulnerable ports
            score += 0.3

        # Private IP to public IP (potential data exfiltration)
        if self._is_private_ip(event.source_ip) and not self._is_private_ip(event.dest_ip):
            score += 0.2

        return min(1.0, score)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first = int(parts[0])
            second = int(parts[1])

            # Private IP ranges
            return (first == 10 or
                   (first == 172 and 16 <= second <= 31) or
                   (first == 192 and second == 168))
        except:
            return False

    def _assess_threats(self, events: List[NetworkEvent]) -> ThreatAssessment:
        """Analyze events and assess threat level using sophisticated AI analysis"""
        if not events:
            return ThreatAssessment(
                threat_level=ThreatLevel.LOW,
                confidence=0.9,
                indicators=[],
                recommended_actions=[ActionType.MONITOR]
            )

        try:
            # Convert NetworkEvent to LiveNetworkEvent for AI threat detector
            live_events = []
            for event in events:
                live_event = self._convert_network_event_to_live_event(event)
                live_events.append(live_event)

            # Use sophisticated AI threat detection
            ai_assessment = self.ai_threat_detector.analyze_events_for_threats(live_events)

            # Enhance with memory-based pattern matching
            memory_indicators = []
            memory_score = 0.0

            # Check against known patterns from memory
            event_indicators = [f"{e.protocol}:{e.source_ip}" for e in events]
            similar_patterns = self.memory.get_similar_patterns(event_indicators)

            if similar_patterns:
                highest_threat = max(similar_patterns, key=lambda x: x['confidence'])
                memory_score = highest_threat['confidence']
                memory_indicators.append(f"Similar to known pattern: {highest_threat['pattern_type']} (seen {highest_threat['occurrence_count']} times)")

            # Combine AI assessment with memory-based assessment
            combined_confidence = max(ai_assessment.confidence, memory_score)
            combined_indicators = ai_assessment.indicators + memory_indicators

            # Adaptive confidence boosting based on pattern history
            if memory_score > 0.5 and len(similar_patterns) > 0:
                # Boost confidence if we've seen similar patterns multiple times
                pattern_multiplier = min(1.2, 1.0 + (len(similar_patterns) * 0.1))
                combined_confidence = min(0.95, combined_confidence * pattern_multiplier)
                combined_indicators.append(f"Confidence boosted by pattern history (multiplier: {pattern_multiplier:.2f})")

            # Use AI assessment's threat level but with combined confidence
            final_assessment = ThreatAssessment(
                threat_level=ai_assessment.threat_level,
                confidence=combined_confidence,
                indicators=combined_indicators,
                recommended_actions=ai_assessment.recommended_actions
            )

            # Log the analysis for debugging
            self.logger.debug(f"Threat assessment: {final_assessment.threat_level.name} (confidence: {final_assessment.confidence:.2f})")
            self.logger.debug(f"Indicators: {len(final_assessment.indicators)} found")

            return final_assessment

        except Exception as e:
            self.logger.error(f"Error in AI threat assessment: {e}")
            # Fallback to basic assessment
            return self._basic_threat_assessment(events)

    def _convert_network_event_to_live_event(self, network_event: NetworkEvent):
        """Convert NetworkEvent to LiveNetworkEvent for AI analysis"""
        try:
            from src.live_capture import LiveNetworkEvent
        except ImportError:
            from live_capture import LiveNetworkEvent

        return LiveNetworkEvent(
            timestamp=network_event.timestamp,
            source_ip=network_event.source_ip,
            dest_ip=network_event.dest_ip,
            protocol=network_event.protocol,
            size=network_event.size,
            port=network_event.event_data.get('port'),
            raw_packet=None
        )

    def _basic_threat_assessment(self, events: List[NetworkEvent]) -> ThreatAssessment:
        """Fallback basic threat assessment if AI analysis fails"""
        indicators = []
        threat_score = 0.0

        # Check against known patterns from memory
        event_indicators = [f"{e.protocol}:{e.source_ip}" for e in events]
        similar_patterns = self.memory.get_similar_patterns(event_indicators)

        if similar_patterns:
            highest_threat = max(similar_patterns, key=lambda x: x['confidence'])
            threat_score = highest_threat['confidence']
            indicators.append(f"Similar to known pattern: {highest_threat['pattern_type']}")

        # Determine threat level
        if threat_score > 0.8:
            threat_level = ThreatLevel.CRITICAL
            actions = [ActionType.BLOCK_IP, ActionType.ALERT, ActionType.ESCALATE]
        elif threat_score > 0.6:
            threat_level = ThreatLevel.HIGH
            actions = [ActionType.ALERT, ActionType.INVESTIGATE]
        elif threat_score > 0.3:
            threat_level = ThreatLevel.MEDIUM
            actions = [ActionType.INVESTIGATE, ActionType.MONITOR]
        else:
            threat_level = ThreatLevel.LOW
            actions = [ActionType.MONITOR]

        return ThreatAssessment(
            threat_level=threat_level,
            confidence=max(0.1, threat_score),
            indicators=indicators,
            recommended_actions=actions
        )

    def _decide_actions(self, assessment: ThreatAssessment,
                       events: List[NetworkEvent]) -> List[AgentAction]:
        """Decide what actions to take based on threat assessment - DECIDE phase"""
        self.last_decision_time = datetime.now()

        actions = []

        # Choose actions based on threat level, agent goals, and learned effectiveness
        for action_type in assessment.recommended_actions:
            if self._should_take_action(action_type, assessment):
                target = self._determine_action_target(action_type, events)

                # Get feedback-based recommendation for this action
                context = {
                    'threat_level': assessment.threat_level.name,
                    'indicators': assessment.indicators,
                    'event_count': len(events)
                }

                recommendation = self.feedback_collector.get_action_recommendation(
                    action_type.value, target, assessment.confidence, context
                )

                # Adjust confidence based on historical effectiveness
                adjusted_confidence = self._adjust_confidence_with_feedback(
                    assessment.confidence, recommendation
                )

                # Create action with enhanced information
                action = AgentAction(
                    action_type=action_type,
                    target=target,
                    reason=f"Threat level {assessment.threat_level.name} with {adjusted_confidence:.2f} confidence (expected effectiveness: {recommendation['expected_effectiveness']:.2f})",
                    confidence=adjusted_confidence,
                    timestamp=datetime.now()
                )
                actions.append(action)

                # Log the recommendation influence
                if recommendation['sample_size'] > 0:
                    self.logger.debug(f"Action {action_type.value} recommendation: {recommendation['recommended']} "
                                    f"(expected effectiveness: {recommendation['expected_effectiveness']:.2f}, "
                                    f"based on {recommendation['sample_size']} samples)")

        return actions

    def _adjust_confidence_with_feedback(self, original_confidence: float,
                                       recommendation: Dict[str, Any]) -> float:
        """Adjust confidence based on historical feedback"""

        if recommendation['sample_size'] < 3:
            # Not enough data, return original confidence
            return original_confidence

        expected_effectiveness = recommendation['expected_effectiveness']
        prediction_confidence = recommendation['confidence_in_prediction']

        # Adjust confidence based on expected effectiveness
        if expected_effectiveness > 0.8:
            # High expected effectiveness - boost confidence slightly
            adjustment = 0.1 * prediction_confidence
            return min(0.95, original_confidence + adjustment)
        elif expected_effectiveness < 0.3:
            # Low expected effectiveness - reduce confidence
            adjustment = 0.2 * prediction_confidence
            return max(0.1, original_confidence - adjustment)
        else:
            # Moderate effectiveness - minor adjustment toward expected
            diff = expected_effectiveness - 0.5
            adjustment = diff * 0.1 * prediction_confidence
            return max(0.1, min(0.95, original_confidence + adjustment))

    def _should_take_action(self, action_type: ActionType,
                           assessment: ThreatAssessment) -> bool:
        """Decide whether to take a specific action based on agent goals and adaptive thresholds"""

        # Get adaptive thresholds based on agent performance and goals
        adaptive_thresholds = self._get_adaptive_thresholds()

        # Consider false positive rate and agent goals for aggressive actions
        if action_type == ActionType.BLOCK_IP:
            # Require high confidence and high/critical threat level
            confidence_threshold = adaptive_thresholds.get('block_ip_confidence', 0.8)
            return (assessment.confidence > confidence_threshold and
                   assessment.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL])

        elif action_type == ActionType.ALERT:
            # More lenient for alerts since they're non-disruptive
            confidence_threshold = adaptive_thresholds.get('alert_confidence', 0.4)
            return assessment.confidence > confidence_threshold

        elif action_type == ActionType.INVESTIGATE:
            # Investigate on medium confidence - it's better to investigate too much than too little
            confidence_threshold = adaptive_thresholds.get('investigate_confidence', 0.25)
            return assessment.confidence > confidence_threshold

        elif action_type == ActionType.ESCALATE:
            # Escalate on critical threats regardless of confidence, or high confidence high threats
            return (assessment.threat_level == ThreatLevel.CRITICAL or
                   (assessment.threat_level == ThreatLevel.HIGH and assessment.confidence > 0.85))

        else:  # MONITOR
            return True

    def _get_adaptive_thresholds(self) -> Dict[str, float]:
        """Get adaptive thresholds based on agent performance and environment"""
        # Base thresholds
        thresholds = {
            'block_ip_confidence': 0.8,
            'alert_confidence': 0.4,
            'investigate_confidence': 0.25
        }

        # Apply risk tolerance scaling first (Phase 5 config)
        risk = self._get_risk_tolerance()  # 0.5..1.5
        # Higher risk tolerance lowers thresholds (more aggressive); lower risk raises them
        thresholds['block_ip_confidence'] = max(0.5, min(0.95, thresholds['block_ip_confidence'] / risk))
        thresholds['alert_confidence'] = max(0.1, min(0.9, thresholds['alert_confidence'] / risk))
        thresholds['investigate_confidence'] = max(0.05, min(0.6, thresholds['investigate_confidence'] / risk))

        # Adjust based on false positive rate
        false_positive_rate = self._calculate_false_positive_rate()

        if false_positive_rate > 0.1:  # If >10% false positives, be more conservative
            adjustment = min(0.2, false_positive_rate)
            thresholds['block_ip_confidence'] += adjustment
            thresholds['alert_confidence'] += adjustment * 0.5
            self.logger.debug(f"Raised thresholds due to high false positive rate: {false_positive_rate:.2%}")

        elif false_positive_rate < 0.02:  # If <2% false positives, be more aggressive
            adjustment = 0.05
            thresholds['block_ip_confidence'] = max(0.6, thresholds['block_ip_confidence'] - adjustment)
            thresholds['alert_confidence'] = max(0.2, thresholds['alert_confidence'] - adjustment)
            self.logger.debug(f"Lowered thresholds due to low false positive rate: {false_positive_rate:.2%}")

        # Adjust based on threat environment
        if hasattr(self, 'recent_threat_density'):
            threat_density = getattr(self, 'recent_threat_density', 0.1)
            if threat_density > 0.3:  # High threat environment - be more aggressive
                thresholds['investigate_confidence'] *= 0.8
                self.logger.debug(f"Lowered investigation threshold due to high threat density: {threat_density:.2%}")

        return thresholds

    def _calculate_false_positive_rate(self) -> float:
        """Calculate false positive rate from feedback data"""
        try:
            # Use real feedback data if available
            feedback_summary = self.feedback_collector.get_feedback_summary()
            return feedback_summary['feedback_metrics']['false_positive_rate']
        except:
            # Fallback to simple calculation
            failed_actions = self.metrics.get('failed_actions', 0)
            total_actions = self.metrics.get('actions_taken', 1)
            return min(0.2, failed_actions / max(1, total_actions))

    def _determine_action_target(self, action_type: ActionType,
                                events: List[NetworkEvent]) -> str:
        """Determine the target for an action"""
        if not events:
            return "network"

        if action_type == ActionType.BLOCK_IP:
            # Target the most suspicious source IP
            suspicious_event = max(events, key=lambda e: e.suspicious_score)
            return suspicious_event.source_ip

        return "network"

    def _execute_action(self, action: AgentAction):
        """Execute the chosen action - ACT phase using real action executor"""
        try:
            self.logger.info(f"🎯 Executing action: {action.action_type.value} on {action.target}")
            self.logger.info(f"   Reason: {action.reason}")

            executed_action = None

            if action.action_type == ActionType.BLOCK_IP:
                executed_action = self.action_executor.execute_block_ip(action.target, action.reason)
            elif action.action_type == ActionType.ALERT:
                executed_action = self.action_executor.execute_send_alert(action.reason, action.confidence, action.target)
            elif action.action_type == ActionType.INVESTIGATE:
                executed_action = self.action_executor.execute_start_investigation(action.target, action.reason)
            elif action.action_type == ActionType.ESCALATE:
                executed_action = self.action_executor.execute_escalate_to_human(action.reason, action.confidence)
            # MONITOR action is passive - no real action needed

            # Track execution results and start feedback monitoring
            if executed_action:
                self.logger.info(f"   Result: {executed_action.result.value} - {executed_action.details}")

                # Start feedback monitoring for this action
                if executed_action.result.value in ['success', 'skipped']:
                    self._start_feedback_monitoring(action, executed_action)
                    self.metrics['actions_taken'] += 1
                else:
                    self.metrics['failed_actions'] = self.metrics.get('failed_actions', 0) + 1
                # Track immediate effectiveness marker
                self._track_action_effectiveness(action, executed_action.result.value)
            else:
                self.metrics['actions_taken'] += 1  # For MONITOR actions

        except Exception as e:
            self.logger.error(f"Failed to execute action {action.action_type}: {e}")
            self.metrics['failed_actions'] = self.metrics.get('failed_actions', 0) + 1

    def _start_feedback_monitoring(self, action: AgentAction, executed_action: Any) -> None:
        """Start FeedbackCollector monitoring and seed context for effectiveness tracking."""
        try:
            # Seed blocked IP state for effectiveness checks
            if action.action_type == ActionType.BLOCK_IP and action.target:
                try:
                    self.feedback_collector.set_blocked_ip(action.target)
                except Exception:
                    pass

            # Compose monitoring context
            context = {
                'threat_level': 'unknown',
                'indicators': [],
            }
            # If we kept last assessment, enrich context
            try:
                if hasattr(self, 'recent_assessments') and self.recent_assessments:
                    last = self.recent_assessments[-1]
                    context['threat_level'] = last['threat_level'].name if hasattr(last['threat_level'], 'name') else str(last['threat_level'])
                    context['indicators'] = []
            except Exception:
                pass

            self.feedback_collector.start_action_monitoring(
                action_id=getattr(executed_action, 'action_id', f"{action.action_type.value}_{int(time.time())}"),
                action_type=action.action_type.value,
                target=action.target,
                confidence=action.confidence,
                threat_level=context.get('threat_level', 'unknown'),
                context=context,
            )
        except Exception as e:
            self.logger.debug(f"Feedback monitoring not started: {e}")

    def _track_action_effectiveness(self, action: AgentAction, outcome: str):
        """Record immediate outcome context; long-term tracking handled by FeedbackCollector."""
        try:
            # Light-touch: increment counters for quick adaptation
            if outcome.lower() not in ["success", "skipped"]:
                self.metrics['failed_actions'] = self.metrics.get('failed_actions', 0) + 1
        except Exception:
            pass


    def _learn_from_experience(self, events: List[NetworkEvent],
                              assessment: ThreatAssessment, actions: List[AgentAction]):
        """Enhanced learning from this monitoring cycle - LEARN phase"""

        # Store significant threat patterns
        if events and assessment.threat_level != ThreatLevel.LOW:
            # Create more detailed indicators including behavioral patterns
            indicators = []

            # Protocol and source patterns
            indicators.extend([f"{e.protocol}:{e.source_ip}" for e in events])

            # Traffic volume patterns
            total_bytes = sum(e.size for e in events)
            unique_destinations = len(set(e.dest_ip for e in events))
            unique_protocols = len(set(e.protocol for e in events))

            indicators.extend([
                f"volume:{total_bytes}",
                f"destinations:{unique_destinations}",
                f"protocols:{unique_protocols}"
            ])

            # Time-based patterns
            if len(events) > 1:
                time_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
                event_rate = len(events) / max(1, time_span)
                indicators.append(f"rate:{event_rate:.2f}")

            # Store the enhanced pattern
            self.memory.remember_threat_pattern(
                pattern_type=f"ai_threat_{assessment.threat_level.name.lower()}",
                indicators=indicators,
                threat_level=assessment.threat_level,
                confidence=assessment.confidence
            )

            self.logger.debug(f"Learned threat pattern with {len(indicators)} indicators")

        # Update threat environment metrics
        self._update_threat_environment_metrics(events, assessment, actions)

        # Learn from action effectiveness (basic version - will be enhanced in Phase 4)
        self._learn_from_action_outcomes(actions)

    def _update_threat_environment_metrics(self, events: List[NetworkEvent],
                                         assessment: ThreatAssessment, actions: List[AgentAction]):
        """Update metrics about the threat environment"""

        # Calculate recent threat density
        if not hasattr(self, 'recent_assessments'):
            self.recent_assessments = []

        self.recent_assessments.append({
            'timestamp': datetime.now(),
            'threat_level': assessment.threat_level,
            'confidence': assessment.confidence,
            'event_count': len(events)
        })

        # Keep only last 50 assessments for sliding window
        self.recent_assessments = self.recent_assessments[-50:]

        # Calculate threat density (percentage of non-LOW threats)
        non_low_threats = len([a for a in self.recent_assessments
                              if a['threat_level'] != ThreatLevel.LOW])
        self.recent_threat_density = non_low_threats / len(self.recent_assessments)

        # Update metrics
        self.metrics['recent_threat_density'] = self.recent_threat_density
        self.metrics['avg_threat_confidence'] = sum(a['confidence'] for a in self.recent_assessments) / len(self.recent_assessments)

    def _learn_from_action_outcomes(self, actions: List[AgentAction]):
        """Learn from action execution outcomes (basic version)"""

        if not hasattr(self, 'action_history'):
            self.action_history = []

        for action in actions:
            self.action_history.append({
                'timestamp': action.timestamp,
                'action_type': action.action_type.value,
                'confidence': action.confidence,
                'target': action.target
            })

        # Keep only last 100 actions
        self.action_history = self.action_history[-100:]

        # Update action type frequency metrics
        if not hasattr(self, 'action_frequency'):
            self.action_frequency = {}

        for action in actions:
            action_type = action.action_type.value
            self.action_frequency[action_type] = self.action_frequency.get(action_type, 0) + 1

    def _update_performance_metrics(self):
        """Update agent performance metrics"""
        if self.start_time:
            self.metrics['uptime'] = datetime.now() - self.start_time
        # Integrate feedback metrics for visibility/adaptation
        try:
            fb = self.feedback_collector.get_feedback_summary()
            self.metrics['avg_effectiveness'] = fb['feedback_metrics'].get('avg_effectiveness', 0.0)
            self.metrics['avg_response_time'] = fb['feedback_metrics'].get('avg_response_time', 0.0)
            self.metrics['false_positive_rate'] = fb['feedback_metrics'].get('false_positive_rate', 0.0)
        except Exception:
            pass

    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status and performance with enhanced AI metrics"""
        status = {
            'is_running': self.is_running,
            'uptime': str(self.metrics['uptime']),
            'metrics': self.metrics,
            'goals': self.goals,
            'last_decision': self.last_decision_time.isoformat() if self.last_decision_time else None,
            'memory_patterns': len(self.memory.get_similar_patterns([], threshold=0.0))
        }

        # Add AI threat detector status
        if hasattr(self, 'ai_threat_detector'):
            status['ai_threat_detector'] = self.ai_threat_detector.get_detection_stats()

        # Add adaptive threshold information
        if hasattr(self, '_get_adaptive_thresholds'):
            status['adaptive_thresholds'] = self._get_adaptive_thresholds()

        # Add threat environment metrics
        if hasattr(self, 'recent_threat_density'):
            status['threat_environment'] = {
                'recent_threat_density': self.recent_threat_density,
                'avg_threat_confidence': self.metrics.get('avg_threat_confidence', 0.0),
                'recent_assessments_count': len(getattr(self, 'recent_assessments', []))
            }

        # Add action frequency data
        if hasattr(self, 'action_frequency'):
            status['action_frequency'] = self.action_frequency

        # Add false positive rate
        status['false_positive_rate'] = self._calculate_false_positive_rate()

        # Add feedback summary highlights
        try:
            status['feedback'] = self.feedback_collector.get_feedback_summary()
        except Exception:
            pass

        return status

    def _get_risk_tolerance(self) -> float:
        """Return risk tolerance factor in [0.5, 1.5]; lower = conservative, higher = aggressive."""
        try:
            rt = float(self.config.get('risk_tolerance', 1.0))
            return max(0.5, min(1.5, rt))
        except Exception:
            return 1.0
