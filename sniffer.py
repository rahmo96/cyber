"""
Sniffer Module for NetGuard-CLI

Captures and extracts network packet information using Scapy.

Improvements over the original:
  - Deep Packet Inspection (DPI) via dpi.py populates PacketInfo.app_protocol
  - Packet timestamps taken from the captured frame (not time.time()), so
    pcap-replay timestamps are accurate for time-window detections
  - Robust error handling for malformed / truncated packets
  - Optional BPF capture filter passed straight to Scapy
  - High-throughput queue-based dispatch: the sniff callback is minimal and
    pushes raw packets onto a queue; a separate worker thread calls the
    user-supplied callback, preventing packet loss under heavy load
  - Rolling PCAP export buffer: keeps the last N raw Scapy packets so
    suspicious traffic can be saved to disk on demand
"""

import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Iterator, Optional

from scapy.all import IP, Packet, rdpcap, sniff, wrpcap
from scapy.layers.inet import TCP, UDP

from dpi import DeepPacketInspector


@dataclass
class PacketInfo:
    """Structured packet information extracted from a network frame."""
    source_ip: str
    dest_ip: str
    protocol: str
    payload_size: int
    source_port: Optional[int]
    dest_port: Optional[int]
    timestamp: float
    # DPI-identified application-layer protocol (e.g. "HTTP", "TLS", "DNS")
    app_protocol: str = "Unknown"


class NetworkSniffer:
    """
    Network traffic sniffer built on Scapy.

    Supports two capture modes:
      - Live capture from a network interface
      - Simulation / replay from a .pcap file

    Both modes can apply an optional BPF filter string.
    """

    # Number of raw Scapy packets kept in the rolling PCAP export buffer
    PCAP_BUFFER_SIZE = 1000

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: str = "",
    ) -> None:
        """
        Args:
            interface:   Network interface for live capture (None = default).
            pcap_file:   Path to a .pcap file for simulation mode.
            bpf_filter:  BPF filter string, e.g. "tcp port 80".
                         Applied to live capture; pcap files are pre-filtered
                         by iterating and discarding non-matching frames.
        """
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.is_simulation = pcap_file is not None

        self._dpi = DeepPacketInspector()

        # Rolling buffer of raw Scapy Packet objects for on-demand PCAP export
        self._pcap_buffer: Deque[Packet] = deque(maxlen=self.PCAP_BUFFER_SIZE)
        self._buffer_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_capture(self, packet_callback: Callable[[PacketInfo], None]) -> None:
        """
        Start capturing packets and invoke *packet_callback* for each one.

        In live mode a producer/consumer queue decouples the Scapy sniff loop
        from the (potentially slow) analysis callback.  This prevents the
        kernel ring-buffer from overflowing under high traffic.

        Args:
            packet_callback: Called with a PacketInfo for every captured packet.
        """
        if self.is_simulation:
            self._replay_pcap(packet_callback)
        else:
            self._live_capture(packet_callback)

    def capture_packets(self) -> Iterator[PacketInfo]:
        """
        Generator interface: yield PacketInfo objects one at a time.
        Only available in simulation mode for simplicity; prefer
        start_capture() for live capture.
        """
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
        """
        Write the rolling PCAP buffer to *filename*.

        Returns the number of packets written.
        """
        with self._buffer_lock:
            snapshot = list(self._pcap_buffer)

        if not snapshot:
            return 0

        wrpcap(filename, snapshot)
        return len(snapshot)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _replay_pcap(self, callback: Callable[[PacketInfo], None]) -> None:
        """Read every packet from the pcap file and feed it to the callback."""
        try:
            packets = rdpcap(self.pcap_file)
        except FileNotFoundError:
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")
        except Exception as exc:
            raise RuntimeError(f"Error reading PCAP file: {exc}") from exc

        for raw in packets:
            # Apply BPF-style pre-filter when one was requested
            if self.bpf_filter and not self._bpf_matches(raw):
                continue

            info = self._extract_packet_info(raw)
            if info:
                with self._buffer_lock:
                    self._pcap_buffer.append(raw)
                callback(info)
                # Throttle to avoid overwhelming the analysis pipeline
                time.sleep(0.001)

    def _live_capture(self, callback: Callable[[PacketInfo], None]) -> None:
        """
        Capture live packets using a producer/consumer queue so that the
        Scapy sniff() loop is never blocked by slow analysis code.
        """
        pkt_queue: queue.Queue = queue.Queue(maxsize=10_000)
        stop_event = threading.Event()

        def producer(raw: Packet) -> None:
            try:
                pkt_queue.put_nowait(raw)
            except queue.Full:
                # Drop the packet rather than block the capture thread
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
                        pass  # Never let a callback crash the capture loop

        consumer_thread = threading.Thread(target=consumer, daemon=True)
        consumer_thread.start()

        try:
            sniff(
                iface=self.interface or None,
                filter=self.bpf_filter or None,
                prn=producer,
                store=False,
            )
        except (PermissionError, OSError) as exc:
            # On Linux, raw-socket creation without root raises OSError (errno EPERM/EACCES)
            # in addition to Python's PermissionError subclass
            raise PermissionError(
                f"Live packet capture requires root privileges on Linux. "
                f"Run with 'sudo python3 main.py' or grant the capability:\n"
                f"  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))\n"
                f"Original error: {exc}"
            ) from exc
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            raise RuntimeError(f"Error during live capture: {exc}") from exc
        finally:
            stop_event.set()
            consumer_thread.join(timeout=3)

    def _extract_packet_info(self, packet: Packet) -> Optional[PacketInfo]:
        """
        Extract a PacketInfo from a raw Scapy packet.

        Returns None for non-IP frames or on any parsing error.
        Malformed/truncated packets are silently discarded — they must not
        crash the capture loop.
        """
        try:
            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]
            source_ip: str = ip_layer.src
            dest_ip: str = ip_layer.dst

            source_port: Optional[int] = None
            dest_port: Optional[int] = None
            raw_payload: bytes = b""

            if packet.haslayer(TCP):
                protocol = "TCP"
                source_port = int(packet[TCP].sport)
                dest_port = int(packet[TCP].dport)
                raw_payload = bytes(packet[TCP].payload)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                source_port = int(packet[UDP].sport)
                dest_port = int(packet[UDP].dport)
                raw_payload = bytes(packet[UDP].payload)
            else:
                protocol = "Other"
                raw_payload = bytes(ip_layer.payload)

            # Use the frame's own capture timestamp — critical for pcap replay
            timestamp: float = float(packet.time) if packet.time else time.time()

            payload_size: int = len(ip_layer.payload)

            # DPI: identify application-layer protocol from payload bytes
            app_protocol: str = self._dpi.identify(
                raw_payload, source_port, dest_port, protocol
            )

            return PacketInfo(
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                payload_size=payload_size,
                source_port=source_port,
                dest_port=dest_port,
                timestamp=timestamp,
                app_protocol=app_protocol,
            )

        except Exception:
            # Silently discard malformed / truncated packets
            return None

    def _bpf_matches(self, packet: Packet) -> bool:
        """
        Lightweight BPF pre-filter for pcap-replay mode.

        Only the most common predicates are supported (tcp, udp, port N,
        host A.B.C.D).  For full BPF support use Scapy's filter= in live mode.
        """
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
                host = f.split()[1]
                if packet.haslayer(IP):
                    return packet[IP].src == host or packet[IP].dst == host
            except IndexError:
                pass

        # Unknown filter expression — let all packets through rather than
        # silently dropping everything
        return True
