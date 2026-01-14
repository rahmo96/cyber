"""
Sniffer Module for NetGuard-CLI
Captures and extracts network packet information using scapy.
"""

from typing import Optional, Dict, Iterator
from scapy.all import sniff, IP, rdpcap, Packet
from scapy.layers.inet import TCP, UDP
from dataclasses import dataclass
import time


@dataclass
class PacketInfo:
    """Structured packet information extracted from network traffic."""
    source_ip: str
    dest_ip: str
    protocol: str
    payload_size: int
    source_port: Optional[int]
    dest_port: Optional[int]
    timestamp: float


class NetworkSniffer:
    """Network traffic sniffer using scapy."""
    
    def __init__(self, interface: Optional[str] = None, pcap_file: Optional[str] = None):
        """
        Initialize the network sniffer.
        
        Args:
            interface: Network interface to sniff on (None for default)
            pcap_file: Path to .pcap file for simulation mode (None for live capture)
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.is_simulation = pcap_file is not None
    
    def _extract_packet_info(self, packet: Packet) -> Optional[PacketInfo]:
        """
        Extract relevant information from a network packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            PacketInfo object or None if packet is not IP-based
        """
        if not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        source_ip = ip_layer.src
        dest_ip = ip_layer.dst
        
        # Determine protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
        else:
            protocol = "Other"
            source_port = None
            dest_port = None
        
        # Calculate payload size (total packet size minus IP header)
        payload_size = len(packet[IP].payload) if packet.haslayer(IP) else 0
        
        return PacketInfo(
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            payload_size=payload_size,
            source_port=source_port,
            dest_port=dest_port,
            timestamp=time.time()
        )
    
    def _packet_handler(self, packet: Packet) -> Optional[PacketInfo]:
        """Callback handler for scapy sniffing."""
        return self._extract_packet_info(packet)
    
    def capture_packets(self) -> Iterator[PacketInfo]:
        """
        Capture packets either from live interface or pcap file.
        
        Yields:
            PacketInfo objects for each captured packet
        """
        if self.is_simulation:
            # Simulation mode: read from pcap file
            try:
                packets = rdpcap(self.pcap_file)
                for packet in packets:
                    packet_info = self._extract_packet_info(packet)
                    if packet_info:
                        yield packet_info
            except FileNotFoundError:
                raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
            except Exception as e:
                raise RuntimeError(f"Error reading PCAP file: {e}")
        else:
            # Live capture mode
            try:
                sniff(
                    iface=self.interface,
                    prn=lambda p: self._packet_handler(p),
                    stop_filter=False,
                    store=False
                )
            except KeyboardInterrupt:
                raise StopIteration
            except Exception as e:
                raise RuntimeError(f"Error capturing packets: {e}")
    
    def start_capture(self, packet_callback) -> None:
        """
        Start packet capture with a callback function.
        
        Args:
            packet_callback: Function to call with each PacketInfo
        """
        if self.is_simulation:
            # Simulation mode: read from pcap file
            try:
                packets = rdpcap(self.pcap_file)
                for packet in packets:
                    packet_info = self._extract_packet_info(packet)
                    if packet_info:
                        packet_callback(packet_info)
                    # Small delay to prevent overwhelming the system
                    time.sleep(0.001)
            except FileNotFoundError:
                raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
            except Exception as e:
                raise RuntimeError(f"Error reading PCAP file: {e}")
        else:
            # Live capture mode
            def packet_handler(packet: Packet) -> None:
                packet_info = self._extract_packet_info(packet)
                if packet_info:
                    packet_callback(packet_info)
            
            try:
                sniff(
                    iface=self.interface,
                    prn=packet_handler,
                    store=False
                )
            except KeyboardInterrupt:
                pass
            except Exception as e:
                raise RuntimeError(f"Error capturing packets: {e}")

