import openai
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass
import logging
import os
try:
    from src.autonomous_agent import ThreatLevel, ThreatAssessment, ActionType
    from src.live_capture import LiveNetworkEvent
except ImportError:
    from autonomous_agent import ThreatLevel, ThreatAssessment, ActionType
    from live_capture import LiveNetworkEvent

@dataclass
class ThreatIndicator:
    name: str
    description: str
    weight: float
    threshold: float
    current_value: float

class AIThreatDetector:
    """AI-powered threat detection engine with learning capabilities"""

    def __init__(self, openai_api_key: str = None):
        self.api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        self.client = openai.OpenAI(api_key=self.api_key) if self.api_key else None
        self.logger = logging.getLogger(self.__class__.__name__)

        # Detection rules and thresholds
        self.detection_rules = {
            'port_scan': {
                'description': 'Multiple ports accessed from single source',
                'threshold': 10,  # ports per minute
                'weight': 0.8
            },
            'dos_attack': {
                'description': 'High volume of packets from single source',
                'threshold': 100,  # packets per minute
                'weight': 0.9
            },
            'suspicious_protocol': {
                'description': 'Unusual protocol usage patterns',
                'threshold': 0.7,  # anomaly score
                'weight': 0.6
            },
            'data_exfiltration': {
                'description': 'Large outbound data transfers',
                'threshold': 10000000,  # bytes per minute (10MB)
                'weight': 0.8
            },
            'dns_tunneling': {
                'description': 'Excessive DNS queries',
                'threshold': 50,  # DNS queries per minute
                'weight': 0.7
            },
            'lateral_movement': {
                'description': 'Internal network scanning',
                'threshold': 20,  # internal IPs contacted
                'weight': 0.8
            }
        }

        # Baseline learning
        self.baseline_stats = {
            'normal_protocols': Counter(),
            'normal_ports': Counter(),
            'normal_packet_sizes': [],
            'normal_connection_patterns': defaultdict(set)
        }

        self.learning_window = timedelta(hours=24)  # Learn normal behavior over 24 hours
        self.baseline_established = False

    def analyze_events_for_threats(self, events: List[LiveNetworkEvent],
                                  time_window: timedelta = timedelta(minutes=5)) -> ThreatAssessment:
        """Analyze recent network events for threats using multiple detection methods"""

        if not events:
            return ThreatAssessment(
                threat_level=ThreatLevel.LOW,
                confidence=0.1,
                indicators=[],
                recommended_actions=[ActionType.MONITOR]
            )

        # Filter events to the specified time window
        cutoff_time = datetime.now() - time_window
        recent_events = [e for e in events if e.timestamp >= cutoff_time]

        if not recent_events:
            return ThreatAssessment(
                threat_level=ThreatLevel.LOW,
                confidence=0.1,
                indicators=[],
                recommended_actions=[ActionType.MONITOR]
            )

        # Run multiple detection algorithms
        indicators = []
        threat_scores = []

        # 1. Rule-based detection
        rule_indicators, rule_score = self._rule_based_detection(recent_events)
        indicators.extend(rule_indicators)
        threat_scores.append(rule_score)

        # 2. Statistical anomaly detection
        anomaly_indicators, anomaly_score = self._statistical_anomaly_detection(recent_events)
        indicators.extend(anomaly_indicators)
        threat_scores.append(anomaly_score)

        # 3. AI-powered behavioral analysis (if API key available)
        if self.client:
            try:
                ai_indicators, ai_score = self._ai_behavioral_analysis(recent_events)
                indicators.extend(ai_indicators)
                threat_scores.append(ai_score)
            except Exception as e:
                self.logger.warning(f"AI analysis failed: {e}")

        # Combine threat scores
        final_score = max(threat_scores) if threat_scores else 0.0

        # Determine threat level and recommended actions
        threat_level, actions = self._determine_threat_level_and_actions(final_score, indicators)

        return ThreatAssessment(
            threat_level=threat_level,
            confidence=min(0.95, final_score),
            indicators=indicators,
            recommended_actions=actions
        )

    def _rule_based_detection(self, events: List[LiveNetworkEvent]) -> Tuple[List[str], float]:
        """Apply rule-based threat detection"""
        indicators = []
        max_score = 0.0

        # Group events by source IP for analysis
        events_by_source = defaultdict(list)
        for event in events:
            events_by_source[event.source_ip].append(event)

        for source_ip, source_events in events_by_source.items():
            # Port scan detection
            unique_ports = set(e.port for e in source_events if e.port)
            if len(unique_ports) >= self.detection_rules['port_scan']['threshold']:
                score = self.detection_rules['port_scan']['weight']
                max_score = max(max_score, score)
                indicators.append(f"Port scan detected from {source_ip}: {len(unique_ports)} ports accessed")

            # DoS attack detection
            packet_count = len(source_events)
            if packet_count >= self.detection_rules['dos_attack']['threshold']:
                score = self.detection_rules['dos_attack']['weight']
                max_score = max(max_score, score)
                indicators.append(f"High packet volume from {source_ip}: {packet_count} packets")

            # Data exfiltration detection
            total_bytes = sum(e.size for e in source_events)
            if total_bytes >= self.detection_rules['data_exfiltration']['threshold']:
                score = self.detection_rules['data_exfiltration']['weight']
                max_score = max(max_score, score)
                indicators.append(f"Large data transfer from {source_ip}: {total_bytes} bytes")

            # DNS tunneling detection
            dns_count = len([e for e in source_events if e.protocol == 'DNS'])
            if dns_count >= self.detection_rules['dns_tunneling']['threshold']:
                score = self.detection_rules['dns_tunneling']['weight']
                max_score = max(max_score, score)
                indicators.append(f"Excessive DNS queries from {source_ip}: {dns_count} queries")

        # Lateral movement detection (internal network scanning)
        internal_destinations = set()
        for event in events:
            if self._is_internal_ip(event.dest_ip):
                internal_destinations.add(event.dest_ip)

        if len(internal_destinations) >= self.detection_rules['lateral_movement']['threshold']:
            score = self.detection_rules['lateral_movement']['weight']
            max_score = max(max_score, score)
            indicators.append(f"Lateral movement detected: {len(internal_destinations)} internal IPs contacted")

        return indicators, max_score

    def _statistical_anomaly_detection(self, events: List[LiveNetworkEvent]) -> Tuple[List[str], float]:
        """Detect statistical anomalies in network behavior"""
        indicators = []
        anomaly_score = 0.0

        if not self.baseline_established:
            # Still learning baseline behavior
            self._update_baseline(events)
            return [], 0.0

        # Protocol distribution anomaly
        current_protocols = Counter(e.protocol for e in events)
        protocol_anomaly = self._calculate_distribution_anomaly(
            current_protocols, self.baseline_stats['normal_protocols']
        )

        if protocol_anomaly > 0.7:
            anomaly_score = max(anomaly_score, protocol_anomaly)
            indicators.append(f"Unusual protocol distribution detected (anomaly score: {protocol_anomaly:.2f})")

        # Packet size anomaly
        current_sizes = [e.size for e in events]
        if current_sizes and self.baseline_stats['normal_packet_sizes']:
            size_anomaly = self._calculate_size_anomaly(current_sizes)
            if size_anomaly > 0.7:
                anomaly_score = max(anomaly_score, size_anomaly)
                indicators.append(f"Unusual packet sizes detected (anomaly score: {size_anomaly:.2f})")

        return indicators, anomaly_score

    def _ai_behavioral_analysis(self, events: List[LiveNetworkEvent]) -> Tuple[List[str], float]:
        """Use AI to analyze behavioral patterns"""
        if not self.client:
            return [], 0.0

        # Prepare event summary for AI analysis
        event_summary = self._prepare_event_summary(events)

        prompt = f"""
        Analyze this network traffic pattern for potential security threats:

        {event_summary}

        Consider:
        1. Unusual communication patterns
        2. Potential attack signatures
        3. Anomalous behavior patterns
        4. Data exfiltration indicators

        Respond with:
        - Threat score (0.0-1.0)
        - List of specific indicators (max 3)
        - Brief reasoning

        Format as JSON: {{"score": 0.5, "indicators": ["indicator1", "indicator2"], "reasoning": "brief explanation"}}
        """

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing network traffic."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.1
            )

            result = response.choices[0].message.content.strip()

            # Parse JSON response
            import json
            try:
                analysis = json.loads(result)
                score = float(analysis.get('score', 0.0))
                indicators = analysis.get('indicators', [])
                reasoning = analysis.get('reasoning', '')

                # Add reasoning to indicators
                if reasoning:
                    indicators.append(f"AI Analysis: {reasoning}")

                return indicators[:3], score  # Limit to 3 indicators

            except json.JSONDecodeError:
                self.logger.warning("Failed to parse AI analysis response")
                return [], 0.0

        except Exception as e:
            self.logger.error(f"AI analysis error: {e}")
            return [], 0.0

    def _prepare_event_summary(self, events: List[LiveNetworkEvent]) -> str:
        """Prepare a summary of events for AI analysis"""
        if not events:
            return "No events to analyze"

        # Aggregate statistics
        protocols = Counter(e.protocol for e in events)
        sources = Counter(e.source_ip for e in events)
        destinations = Counter(e.dest_ip for e in events)
        total_bytes = sum(e.size for e in events)

        summary = f"""
        Network Events Summary:
        - Total Events: {len(events)}
        - Time Span: {events[0].timestamp} to {events[-1].timestamp}
        - Total Bytes: {total_bytes}

        Top Protocols: {dict(protocols.most_common(5))}
        Top Sources: {dict(sources.most_common(5))}
        Top Destinations: {dict(destinations.most_common(5))}

        Sample Events:
        """

        # Add sample events
        for i, event in enumerate(events[:3]):
            summary += f"  {i+1}. {event.source_ip} -> {event.dest_ip} ({event.protocol}, {event.size} bytes)\n"

        return summary

    def _calculate_distribution_anomaly(self, current: Counter, baseline: Counter) -> float:
        """Calculate anomaly score for distribution changes"""
        if not baseline:
            return 0.0

        # Calculate KL divergence or similar metric
        total_current = sum(current.values())
        total_baseline = sum(baseline.values())

        if total_current == 0 or total_baseline == 0:
            return 0.0

        anomaly = 0.0
        all_keys = set(current.keys()) | set(baseline.keys())

        for key in all_keys:
            p_current = current.get(key, 0) / total_current
            p_baseline = baseline.get(key, 1) / total_baseline  # Smoothing

            if p_current > 0:
                anomaly += p_current * abs(np.log(p_current / p_baseline))

        return min(1.0, anomaly)

    def _calculate_size_anomaly(self, current_sizes: List[int]) -> float:
        """Calculate anomaly score for packet sizes"""
        if not current_sizes or not self.baseline_stats['normal_packet_sizes']:
            return 0.0

        current_mean = np.mean(current_sizes)
        baseline_mean = np.mean(self.baseline_stats['normal_packet_sizes'])
        baseline_std = np.std(self.baseline_stats['normal_packet_sizes'])

        if baseline_std == 0:
            return 0.0

        # Z-score based anomaly
        z_score = abs(current_mean - baseline_mean) / baseline_std
        return min(1.0, z_score / 3.0)  # Normalize to 0-1

    def _update_baseline(self, events: List[LiveNetworkEvent]):
        """Update baseline statistics with normal traffic patterns"""
        for event in events:
            self.baseline_stats['normal_protocols'][event.protocol] += 1
            if event.port:
                self.baseline_stats['normal_ports'][event.port] += 1
            self.baseline_stats['normal_packet_sizes'].append(event.size)

        # Limit baseline size to prevent memory issues
        if len(self.baseline_stats['normal_packet_sizes']) > 10000:
            self.baseline_stats['normal_packet_sizes'] = self.baseline_stats['normal_packet_sizes'][-5000:]

        # Mark baseline as established after sufficient data
        total_events = sum(self.baseline_stats['normal_protocols'].values())
        if total_events >= 1000:  # Need at least 1000 events for baseline
            self.baseline_established = True
            self.logger.info(f"Baseline established with {total_events} events")

    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/private"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            first = int(parts[0])
            second = int(parts[1])

            # Private IP ranges
            if first == 10:
                return True
            elif first == 172 and 16 <= second <= 31:
                return True
            elif first == 192 and second == 168:
                return True

            return False
        except:
            return False

    def _determine_threat_level_and_actions(self, score: float,
                                          indicators: List[str]) -> Tuple[ThreatLevel, List[ActionType]]:
        """Determine threat level and recommended actions based on score"""

        if score >= 0.9:
            return ThreatLevel.CRITICAL, [ActionType.BLOCK_IP, ActionType.ALERT, ActionType.ESCALATE]
        elif score >= 0.7:
            return ThreatLevel.HIGH, [ActionType.ALERT, ActionType.INVESTIGATE, ActionType.BLOCK_IP]
        elif score >= 0.4:
            return ThreatLevel.MEDIUM, [ActionType.INVESTIGATE, ActionType.ALERT]
        elif score >= 0.2:
            return ThreatLevel.LOW, [ActionType.MONITOR, ActionType.INVESTIGATE]
        else:
            return ThreatLevel.LOW, [ActionType.MONITOR]

    def get_detection_stats(self) -> Dict[str, Any]:
        """Get current detection engine statistics"""
        return {
            'baseline_established': self.baseline_established,
            'baseline_events': sum(self.baseline_stats['normal_protocols'].values()),
            'detection_rules': {name: rule['threshold'] for name, rule in self.detection_rules.items()},
            'ai_available': self.client is not None,
            'top_baseline_protocols': dict(self.baseline_stats['normal_protocols'].most_common(10))
        }