"""
Deep Packet Inspection (DPI) Module for NetGuard-CLI

Identifies application-layer protocols by inspecting raw packet payloads
rather than relying solely on port numbers.  Port-based fallback is used
when the payload is empty (e.g. TCP SYN packets) or unrecognised.

Detection order:
  1. Payload signature matching  — reliable, port-independent
  2. Well-known port fallback    — for encrypted / headerless protocols
"""

from typing import Optional


class DeepPacketInspector:
    """
    Stateless inspector that classifies a single packet's application protocol.

    All methods are pure functions — instantiate once and reuse freely across
    threads without any locking.
    """

    # Well-known port → protocol name (used as fallback only)
    _PORT_MAP: dict = {
        20: "FTP-DATA", 21: "FTP",   22: "SSH",        23: "Telnet",
        25: "SMTP",     53: "DNS",   67: "DHCP",        68: "DHCP",
        80: "HTTP",    110: "POP3", 143: "IMAP",       443: "TLS/HTTPS",
        465: "SMTPS",  587: "SMTP", 993: "IMAPS",      995: "POP3S",
       3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
       8080: "HTTP-ALT", 8443: "TLS-ALT", 27017: "MongoDB",
    }

    # HTTP/1.x request verbs (space included to avoid prefix collisions)
    _HTTP_METHODS = (
        b"GET ", b"POST ", b"PUT ", b"DELETE ",
        b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ",
    )

    # FTP client commands
    _FTP_COMMANDS = (b"USER ", b"PASS ", b"RETR ", b"STOR ", b"LIST", b"QUIT")

    # SMTP greetings / commands
    _SMTP_SIGNATURES = (
        b"220 ", b"EHLO ", b"HELO ", b"MAIL FROM", b"RCPT TO", b"DATA\r\n",
    )

    def identify(
        self,
        payload: bytes,
        src_port: Optional[int],
        dst_port: Optional[int],
        transport: str,
    ) -> str:
        """
        Identify the application-layer protocol for one packet.

        Args:
            payload:    Raw layer-4 payload bytes (may be empty).
            src_port:   TCP/UDP source port, or None.
            dst_port:   TCP/UDP destination port, or None.
            transport:  Transport protocol string: "TCP", "UDP", or "Other".

        Returns:
            A protocol name such as "HTTP", "DNS", "TLS", "SSH", or "Unknown".
        """
        if payload:
            detected = self._inspect_payload(payload, transport, src_port, dst_port)
            if detected:
                return detected

        # Port-based fallback — destination first, then source
        for port in (dst_port, src_port):
            if port and port in self._PORT_MAP:
                return self._PORT_MAP[port]

        return "Unknown"

    # ------------------------------------------------------------------
    # Private payload inspectors
    # ------------------------------------------------------------------

    def _inspect_payload(
        self,
        payload: bytes,
        transport: str,
        src_port: Optional[int],
        dst_port: Optional[int],
    ) -> Optional[str]:
        """
        Walk through each protocol detector in order of specificity.
        Returns the protocol name on first match, or None if unrecognised.
        """
        # SSH banner is always plain-text even over TCP
        if payload.startswith(b"SSH-"):
            return "SSH"

        # HTTP/1.x request line
        for method in self._HTTP_METHODS:
            if payload.startswith(method):
                return "HTTP"

        # HTTP/1.x response line
        if payload.startswith(b"HTTP/"):
            return "HTTP"

        # TLS record layer: first byte is content-type (0x14–0x17),
        # followed by the protocol version (major=3, minor=0..4).
        if len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17):
            if payload[1] == 3 and payload[2] in (0, 1, 2, 3, 4):
                return "TLS"

        # DNS — UDP port 53 is definitive; TCP port 53 has a 2-byte length prefix
        if transport == "UDP" and (src_port == 53 or dst_port == 53):
            return "DNS"
        if transport == "TCP" and (src_port == 53 or dst_port == 53) and len(payload) > 2:
            return "DNS"

        # FTP — 3-digit status replies or well-known commands
        if transport == "TCP":
            if (src_port in (20, 21) or dst_port in (20, 21)) and len(payload) >= 3:
                if payload[:3].isdigit():
                    return "FTP"
            if any(payload.upper().startswith(cmd) for cmd in self._FTP_COMMANDS):
                return "FTP"

        # SMTP greeting / commands (case-insensitive)
        payload_upper = payload.upper()
        if any(payload_upper.startswith(sig.upper()) for sig in self._SMTP_SIGNATURES):
            return "SMTP"

        # RDP — TPKT header: 0x03 0x00 <length high> <length low>
        if len(payload) >= 4 and payload[0] == 0x03 and payload[1] == 0x00:
            return "RDP"

        # mDNS / DNS-SD multicast (UDP port 5353)
        if transport == "UDP" and (src_port == 5353 or dst_port == 5353):
            return "mDNS"

        # NTP (UDP port 123) — first byte: LI/VN/Mode, VN must be 1–4
        if transport == "UDP" and (src_port == 123 or dst_port == 123):
            if len(payload) >= 1 and ((payload[0] >> 3) & 0x07) in (1, 2, 3, 4):
                return "NTP"

        return None
