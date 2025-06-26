import struct
from typing import Optional, Dict, Any

def is_quic_packet(payload: bytes, sport: int, dport: int) -> bool:
    try:
        if len(payload) < 1:
            return False

        first_byte = payload[0]

        # Check if QUIC bit is set
        if first_byte & 0x80:
            # Long header packet
            if len(payload) < 5:
                return False
            version = struct.unpack("!I", payload[1:5])[0]
            if version == 0:
                # Version negotiation packet
                return True
            else:
                # Other long header packet
                return True
        else:
            # Short header packet
            return True  # Heuristic detection for short header packets

    except (IndexError, struct.error):
        return False


def parse_quic_packet(payload: bytes) -> Optional[Dict[str, Any]]:
    try:
        first_byte = payload[0]
        packet_type = None
        version = None
        dcid = None
        scid = None

        if first_byte & 0x80:
            # Long Header
            version = struct.unpack("!I", payload[1:5])[0]
            if version == 0:
                packet_type = "Version Negotiation"
            else:
                if first_byte & 0x30 == 0x00:
                    packet_type = "Initial"
                elif first_byte & 0x30 == 0x10:
                    packet_type = "0-RTT"
                elif first_byte & 0x30 == 0x20:
                    packet_type = "Handshake"
                elif first_byte & 0x30 == 0x30:
                    packet_type = "Retry"

            # ... (Parsing DCID, SCID and other fields based on packet type) ...
            # This section is omitted for brevity, but should be implemented for a 
            # complete parser according to the protocol specification.

        else:
            # Short Header
            packet_type = "Short Header"
            # ... (Parsing DCID and other fields) ...

        return {
            "type": "QUIC",
            "packet_type": packet_type,
            "version": version,
            "dcid": dcid,
            "scid": scid,
             # ... other parsed fields
        }
    except (IndexError, struct.error) as e:
        return {"type": "QUIC", "error": str(e)}


def register() -> Dict[str, Any]:
    return {
        "name": "QUIC",
        "function": is_quic_packet,
        "parser_function": parse_quic_packet,
        "subscriptions": {
            "port_based": [
                {"protocol": "UDP", "port": 443} # According to the document, it uses heuristic method and UDP port 443.
            ]
        }
    }