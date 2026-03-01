"""Sniffer: Capture + Extract. Raw packets -> PacketInfo for analyzer."""

import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Iterator, Optional

from scapy.all import IP, Packet, rdpcap, sniff, wrpcap
from scapy.layers.inet import TCP, UDP
from .dpi import DeepPacketInspector

@dataclass
class PacketInfo:
    """One packet summarized for HSE detection."""
    source_ip: str
    dest_ip: str
    protocol: str
    payload_size: int
    source_port: Optional[int]
    dest_port: Optional[int]
    timestamp: float
    app_protocol: str = "Unknown"

class NetworkSniffer:
    """Captures packets (live or pcap) and yields PacketInfo."""

    PCAP_BUFFER_SIZE = 1000

    def __init__(self, interface: Optional[str] = None, pcap_file: Optional[str] = None, bpf_filter: str = "") -> None:
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.is_simulation = pcap_file is not None
        self._dpi = DeepPacketInspector()
        self._pcap_buffer: Deque[Packet] = deque(maxlen=self.PCAP_BUFFER_SIZE)
        self._buffer_lock = threading.Lock()

    def start_capture(self, packet_callback: Callable[[PacketInfo], None]) -> None:
        if self.is_simulation:
            self._replay_pcap(packet_callback)
        else:
            self._live_capture(packet_callback)

    def capture_packets(self) -> Iterator[PacketInfo]:
        if not self.is_simulation:
            raise RuntimeError("capture_packets() is only supported in simulation mode.")
        try:
            packets = rdpcap(self.pcap_file)
        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        except Exception as exc:
            raise RuntimeError(f"Error reading PCAP file: {exc}") from exc
        for raw in packets:
            info = self._extract_packet_info(raw)
            if info:
                yield info

    def export_pcap(self, filename: str) -> int:
        with self._buffer_lock:
            snapshot = list(self._pcap_buffer)
        if not snapshot:
            return 0
        wrpcap(filename, snapshot)
        return len(snapshot)

    def _replay_pcap(self, callback: Callable[[PacketInfo], None]) -> None:
        try:
            packets = rdpcap(self.pcap_file)
        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        except Exception as exc:
            raise RuntimeError(f"Error reading PCAP file: {exc}") from exc
        for raw in packets:
            if self.bpf_filter and not self._bpf_matches(raw):
                continue
            info = self._extract_packet_info(raw)
            if info:
                with self._buffer_lock:
                    self._pcap_buffer.append(raw)
                callback(info)
                time.sleep(0.001)

    def _live_capture(self, callback: Callable[[PacketInfo], None]) -> None:
        pkt_queue: queue.Queue = queue.Queue(maxsize=10_000)
        stop_event = threading.Event()

        def producer(raw: Packet) -> None:
            try:
                pkt_queue.put_nowait(raw)
            except queue.Full:
                pass

        def consumer() -> None:
            while not stop_event.is_set() or not pkt_queue.empty():
                try:
                    raw = pkt_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                info = self._extract_packet_info(raw)
                if info:
                    with self._buffer_lock:
                        self._pcap_buffer.append(raw)
                    try:
                        callback(info)
                    except Exception:
                        pass

        consumer_thread = threading.Thread(target=consumer, daemon=True)
        consumer_thread.start()
        iface: object = self.interface
        if not iface:
            try:
                from scapy.interfaces import get_if_list
                iface = get_if_list() or None
            except Exception:
                iface = None
        try:
            sniff(iface=iface, filter=self.bpf_filter or None, prn=producer, store=False)
        except (PermissionError, OSError) as exc:
            raise PermissionError(f"Live capture needs root. sudo python3 main.py or setcap. Error: {exc}") from exc
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            raise RuntimeError(f"Error during live capture: {exc}") from exc
        finally:
            stop_event.set()
            consumer_thread.join(timeout=3)

    def _extract_packet_info(self, packet: Packet) -> Optional[PacketInfo]:
        try:
            if not packet.haslayer(IP):
                return None
            ip_layer = packet[IP]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            sport, dport, raw_payload = None, None, b""
            if packet.haslayer(TCP):
                protocol, sport, dport = "TCP", int(packet[TCP].sport), int(packet[TCP].dport)
                raw_payload = bytes(packet[TCP].payload)
            elif packet.haslayer(UDP):
                protocol, sport, dport = "UDP", int(packet[UDP].sport), int(packet[UDP].dport)
                raw_payload = bytes(packet[UDP].payload)
            else:
                protocol, raw_payload = "Other", bytes(ip_layer.payload)
            ts = float(packet.time) if packet.time else time.time()
            return PacketInfo(src_ip, dst_ip, protocol, len(ip_layer.payload), sport, dport, ts,
                self._dpi.identify(raw_payload, sport, dport, protocol))
        except Exception:
            return None

    def _bpf_matches(self, packet: Packet) -> bool:
        f = self.bpf_filter.lower().strip()
        if not f:
            return True
        if f == "tcp":
            return packet.haslayer(TCP)
        if f == "udp":
            return packet.haslayer(UDP)
        if f.startswith("port "):
            try:
                port = int(f.split()[1])
                if packet.haslayer(TCP):
                    return packet[TCP].sport == port or packet[TCP].dport == port
                if packet.haslayer(UDP):
                    return packet[UDP].sport == port or packet[UDP].dport == port
            except (IndexError, ValueError):
                pass
        if f.startswith("host "):
            try:
                if packet.haslayer(IP):
                    return packet[IP].src == f.split()[1] or packet[IP].dst == f.split()[1]
            except IndexError:
                pass
        return True
