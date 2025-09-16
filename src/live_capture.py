import pyshark
import threading
import queue
import time
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from collections import defaultdict, deque
import subprocess
import platform

@dataclass
class LiveNetworkEvent:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    size: int
    port: Optional[int]
    raw_packet: Any

class LiveNetworkCapture:
    """Live network traffic capture system for autonomous monitoring"""

    def __init__(self, interface: str = None, capture_filter: str = None):
        self.interface = interface or self._get_default_interface()
        self.capture_filter = capture_filter or "ip"  # Basic IP traffic filter
        self.logger = logging.getLogger(self.__class__.__name__)

        # Capture state
        self.is_capturing = False
        self.capture_thread = None
        self.capture_object = None

        # Event processing
        self.event_queue = queue.Queue(maxsize=1000)
        self.event_buffer = deque(maxlen=100)  # Keep last 100 events
        self.event_callbacks: List[Callable[[LiveNetworkEvent], None]] = []

        # Statistics
        self.stats = {
            'packets_captured': 0,
            'events_processed': 0,
            'capture_start_time': None,
            'last_packet_time': None,
            'protocols': defaultdict(int),
            'top_sources': defaultdict(int),
            'top_destinations': defaultdict(int)
        }

    def _get_default_interface(self) -> str:
        """Get the default network interface for the system"""
        try:
            if platform.system() == "Darwin":  # macOS
                # Get default route interface
                result = subprocess.run(['route', 'get', 'default'],
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'interface:' in line:
                        return line.split(':')[1].strip()
                return "en0"  # Fallback to common macOS interface

            elif platform.system() == "Linux":
                # Get default route interface
                result = subprocess.run(['ip', 'route', 'show', 'default'],
                                      capture_output=True, text=True)
                if result.stdout:
                    parts = result.stdout.split()
                    dev_index = parts.index('dev') if 'dev' in parts else -1
                    if dev_index >= 0 and dev_index + 1 < len(parts):
                        return parts[dev_index + 1]
                return "eth0"  # Fallback

            else:  # Windows
                return "1"  # Default interface number for Windows

        except Exception as e:
            self.logger.warning(f"Could not detect default interface: {e}")
            return "en0"  # Safe fallback

    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        try:
            if platform.system() == "Darwin":  # macOS
                result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
                return result.stdout.strip().split()

            elif platform.system() == "Linux":
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ': ' in line and 'state' in line:
                        interface = line.split(':')[1].strip().split('@')[0]
                        if interface != 'lo':  # Skip loopback
                            interfaces.append(interface)
                return interfaces

            else:  # Windows - use pyshark to get interfaces
                # This is a simplified approach for Windows
                return ["1", "2", "3", "4", "5"]  # Interface numbers

        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return [self.interface]

    def add_event_callback(self, callback: Callable[[LiveNetworkEvent], None]):
        """Add a callback function to process live network events"""
        self.event_callbacks.append(callback)

    def start_capture(self):
        """Start live network traffic capture"""
        if self.is_capturing:
            self.logger.warning("Capture is already running")
            return

        try:
            self.logger.info(f"🎯 Starting live capture on interface: {self.interface}")
            self.logger.info(f"📡 Capture filter: {self.capture_filter}")

            # Start the capture in a separate thread
            self.is_capturing = True
            self.stats['capture_start_time'] = datetime.now()

            self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.capture_thread.start()

            # Start event processing thread
            self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
            self.processing_thread.start()

            self.logger.info("✅ Live capture started successfully")

        except Exception as e:
            self.logger.error(f"Failed to start capture: {e}")
            self.is_capturing = False
            raise

    def stop_capture(self):
        """Stop live network traffic capture"""
        if not self.is_capturing:
            return

        self.logger.info("🛑 Stopping live capture...")
        self.is_capturing = False

        # Stop the capture object
        if self.capture_object:
            try:
                self.capture_object.close()
            except:
                pass

        # Wait for threads to finish
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        if hasattr(self, 'processing_thread'):
            self.processing_thread.join(timeout=5)

        self.logger.info("✅ Live capture stopped")

    def _capture_loop(self):
        """Main capture loop running in separate thread"""
        try:
            # Create live capture object
            self.capture_object = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter=self.capture_filter
            )

            self.logger.info(f"📡 Starting packet capture on {self.interface}")

            # Capture packets
            for packet in self.capture_object.sniff_continuously():
                if not self.is_capturing:
                    break

                try:
                    event = self._packet_to_event(packet)
                    if event:
                        # Add to queue for processing
                        if not self.event_queue.full():
                            self.event_queue.put(event)

                        # Update statistics
                        self.stats['packets_captured'] += 1
                        self.stats['last_packet_time'] = datetime.now()
                        self.stats['protocols'][event.protocol] += 1
                        self.stats['top_sources'][event.source_ip] += 1
                        self.stats['top_destinations'][event.dest_ip] += 1

                except Exception as e:
                    self.logger.debug(f"Error processing packet: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Capture loop error: {e}")
        finally:
            self.is_capturing = False

    def _packet_to_event(self, packet) -> Optional[LiveNetworkEvent]:
        """Convert pyshark packet to LiveNetworkEvent"""
        try:
            # Extract basic packet information
            timestamp = datetime.now()
            protocol = packet.highest_layer if hasattr(packet, 'highest_layer') else 'UNKNOWN'

            # Get packet size
            size = 0
            if hasattr(packet, 'frame_info') and hasattr(packet.frame_info, 'len'):
                size = int(packet.frame_info.len)
            elif hasattr(packet, 'length'):
                size = int(packet.length)

            # Extract IP addresses
            source_ip = "unknown"
            dest_ip = "unknown"
            port = None

            if hasattr(packet, 'ip'):
                source_ip = packet.ip.src
                dest_ip = packet.ip.dst

            # Extract port information
            if hasattr(packet, 'tcp'):
                port = int(packet.tcp.dstport)
            elif hasattr(packet, 'udp'):
                port = int(packet.udp.dstport)

            return LiveNetworkEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                size=size,
                port=port,
                raw_packet=packet
            )

        except Exception as e:
            self.logger.debug(f"Error converting packet to event: {e}")
            return None

    def _process_events(self):
        """Process events from the queue and notify callbacks"""
        while self.is_capturing:
            try:
                # Get event from queue with timeout
                event = self.event_queue.get(timeout=1.0)

                # Add to buffer
                self.event_buffer.append(event)

                # Notify all callbacks
                for callback in self.event_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        self.logger.error(f"Error in event callback: {e}")

                self.stats['events_processed'] += 1

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing events: {e}")

    def get_recent_events(self, count: int = 50) -> List[LiveNetworkEvent]:
        """Get the most recent network events"""
        return list(self.event_buffer)[-count:]

    def get_capture_stats(self) -> Dict[str, Any]:
        """Get current capture statistics"""
        uptime = None
        if self.stats['capture_start_time']:
            uptime = str(datetime.now() - self.stats['capture_start_time'])

        return {
            'is_capturing': self.is_capturing,
            'interface': self.interface,
            'filter': self.capture_filter,
            'uptime': uptime,
            'packets_captured': self.stats['packets_captured'],
            'events_processed': self.stats['events_processed'],
            'queue_size': self.event_queue.qsize(),
            'buffer_size': len(self.event_buffer),
            'last_packet_time': self.stats['last_packet_time'].isoformat() if self.stats['last_packet_time'] else None,
            'top_protocols': dict(sorted(self.stats['protocols'].items(),
                                       key=lambda x: x[1], reverse=True)[:10]),
            'top_sources': dict(sorted(self.stats['top_sources'].items(),
                                     key=lambda x: x[1], reverse=True)[:10]),
            'top_destinations': dict(sorted(self.stats['top_destinations'].items(),
                                          key=lambda x: x[1], reverse=True)[:10])
        }

    def simulate_network_events(self, duration: int = 60):
        """Simulate network events for testing (when live capture isn't available)"""
        import random

        self.logger.info(f"🧪 Starting network event simulation for {duration} seconds")
        self.is_capturing = True
        self.stats['capture_start_time'] = datetime.now()

        protocols = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP', 'SMTP']
        source_ips = ['192.168.1.100', '192.168.1.101', '10.0.0.5', '172.16.0.10']
        dest_ips = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '172.16.0.1']

        start_time = time.time()

        while self.is_capturing and (time.time() - start_time) < duration:
            # Create simulated event
            event = LiveNetworkEvent(
                timestamp=datetime.now(),
                source_ip=random.choice(source_ips),
                dest_ip=random.choice(dest_ips),
                protocol=random.choice(protocols),
                size=random.randint(64, 1500),
                port=random.choice([80, 443, 53, 22, 21, 25]),
                raw_packet=None
            )

            # Add to buffer and notify callbacks
            self.event_buffer.append(event)
            for callback in self.event_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    self.logger.error(f"Error in simulation callback: {e}")

            # Update stats
            self.stats['packets_captured'] += 1
            self.stats['events_processed'] += 1
            self.stats['protocols'][event.protocol] += 1
            self.stats['top_sources'][event.source_ip] += 1
            self.stats['top_destinations'][event.dest_ip] += 1

            # Random delay between events
            time.sleep(random.uniform(0.1, 2.0))

        self.is_capturing = False
        self.logger.info("🧪 Network simulation completed")


# Backwards compatibility
class LiveCapture:
    def __init__(self, interface: str):
        self.interface = interface

    def capture_packets(self):
        """Captures packets live from the specified interface."""
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            return capture.sniff_continuously()
        except Exception as e:
            print(f"Error starting live capture: {e}")
            return iter([])