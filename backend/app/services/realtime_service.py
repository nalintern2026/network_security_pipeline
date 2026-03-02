"""
Realtime / Active Monitoring Service.
Captures packets, builds flows, classifies via decision engine, inserts into DB.
Runs in background thread; never blocks FastAPI event loop.
"""
import logging
import threading
import uuid
from collections import defaultdict
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Max packets per capture window to avoid memory exhaustion
MAX_PACKETS_PER_WINDOW = 50000

# Protocol number to name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}


def _get_protocol_name(num: int) -> str:
    return PROTOCOL_MAP.get(int(num) if num is not None else 0, str(num) if num else "Unknown")


# Throttle repeated capture failures (log at most once per 30s)
_capture_fail_log_time = 0.0
_capture_fail_count = 0
_last_capture_error: Optional[str] = None


def capture_packets(interface: Optional[str], duration: float = 5) -> List[Any]:
    """Capture packets using scapy. Returns list of packets.
    Run backend with sudo for packet sniffing.
    If specified interface not found, falls back to default (iface=None)."""
    global _capture_fail_log_time, _capture_fail_count, _last_capture_error
    try:
        from scapy.all import sniff
    except ImportError:
        _last_capture_error = "scapy not installed. pip install scapy"
        logger.error(_last_capture_error)
        return []

    # Default/auto: use loopback so we capture local API traffic (frontend↔backend)
    raw = (interface or "").strip()
    iface = raw if raw else "lo"

    try:
        packets = sniff(
            iface=iface,
            timeout=duration,
            count=MAX_PACKETS_PER_WINDOW,
        )
        _last_capture_error = None  # clear on success
        return list(packets) if packets else []
    except Exception as e:
        err_str = str(e).lower()
        # If interface not found, retry with default (captures on all/default interfaces)
        if iface and ("not found" in err_str or "no such device" in err_str):
            try:
                packets = sniff(iface=None, timeout=duration, count=MAX_PACKETS_PER_WINDOW)
                import time
                if time.time() - _capture_fail_log_time > 30:
                    logger.warning(
                        f"Interface '{iface}' not found, using default. "
                        f"Pick a valid interface (e.g. lo, eth0, enp0s3) from Active Monitoring."
                    )
                    _capture_fail_log_time = time.time()
                _last_capture_error = None  # clear on success
                return list(packets) if packets else []
            except Exception as e2:
                import time
                _capture_fail_count += 1
                _last_capture_error = str(e2)
                if time.time() - _capture_fail_log_time > 30:
                    logger.warning(f"Packet capture failed (retry): {e2}")
                    _capture_fail_log_time = time.time()
                return []
        # Throttle log spam for repeated failures (e.g. permission denied)
        import time
        _capture_fail_count += 1
        _last_capture_error = str(e)
        if time.time() - _capture_fail_log_time > 30:
            logger.warning(f"Packet capture failed: {e}")
            _capture_fail_log_time = time.time()
        return []


def build_flows_from_packets(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Group packets by (src_ip, dst_ip, src_port, dst_port, protocol)
    and compute flow stats. Returns list of flow dicts compatible with decision engine.
    """
    if not packets:
        return []

    flows: Dict[tuple, Dict[str, Any]] = defaultdict(lambda: {
        "packets": [],
        "timestamps": [],
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_bytes": 0,
        "syn_count": 0,
    })

    for pkt in packets:
        try:
            if not hasattr(pkt, "payload"):
                continue
            src_ip = pkt.get("IP") or pkt.get("IPv6")
            if src_ip is None:
                continue
            src_ip = str(src_ip.src)
            dst_ip = str(src_ip.dst)

            dst_port = None
            src_port = None
            protocol_num = 6  # TCP default
            syn_count = 0

            if pkt.haslayer("TCP"):
                protocol_num = 6
                tcp = pkt["TCP"]
                src_port = int(tcp.sport) if tcp.sport else None
                dst_port = int(tcp.dport) if tcp.dport else None
                if hasattr(tcp, "flags") and tcp.flags and (tcp.flags & 0x02):  # SYN
                    syn_count = 1
            elif pkt.haslayer("UDP"):
                protocol_num = 17
                udp = pkt["UDP"]
                src_port = int(udp.sport) if udp.sport else None
                dst_port = int(udp.dport) if udp.dport else None
            elif pkt.haslayer("ICMP"):
                protocol_num = 1
                src_port = 0
                dst_port = 0
            else:
                continue

            pkt_len = len(pkt)
            payload_size = pkt_len if pkt.payload else 0

            # Normalize flow key (bidirectional: smaller IP:port first)
            src_tup = (src_ip, src_port or 0)
            dst_tup = (dst_ip, dst_port or 0)
            if src_tup < dst_tup:
                key = (src_ip, dst_ip, src_port or 0, dst_port or 0, protocol_num)
                fwd = True  # packet src->dst is "forward"
            else:
                key = (dst_ip, src_ip, dst_port or 0, src_port or 0, protocol_num)
                fwd = False  # packet src->dst is "backward" in normalized key

            f = flows[key]
            if f["src_ip"] is None:
                f["src_ip"] = key[0]
                f["dst_ip"] = key[1]
                f["src_port"] = key[2]
                f["dst_port"] = key[3]
                f["protocol"] = protocol_num

            f["packets"].append(pkt)
            f["timestamps"].append(float(pkt.time) if hasattr(pkt, "time") else 0)
            if fwd:
                f["fwd_packets"] += 1
                f["fwd_bytes"] += pkt_len
            else:
                f["bwd_packets"] += 1
                f["bwd_bytes"] += pkt_len
            f["syn_count"] += syn_count

        except Exception as e:
            logger.debug(f"Skip packet: {e}")
            continue

    result = []
    for key, f in flows.items():
        if not f["timestamps"]:
            continue
        duration = max(f["timestamps"]) - min(f["timestamps"]) if len(f["timestamps"]) > 1 else 0
        duration = max(duration, 0.000001)
        total_bytes = f["fwd_bytes"] + f["bwd_bytes"]
        total_pkts = f["fwd_packets"] + f["bwd_packets"]

        flow_dict = {
            "src_ip": str(f["src_ip"]),
            "dst_ip": str(f["dst_ip"]),
            "src_port": f["src_port"],
            "dst_port": f["dst_port"],
            "protocol": _get_protocol_name(f["protocol"]),
            "duration": duration,
            "total_fwd_packets": f["fwd_packets"],
            "total_bwd_packets": f["bwd_packets"],
            "total_length_fwd": f["fwd_bytes"],
            "total_length_bwd": f["bwd_bytes"],
            "flow_bytes_per_sec": total_bytes / duration,
            "flow_packets_per_sec": total_pkts / duration,
            "syn_flag_count": f["syn_count"],
        }
        result.append(flow_dict)

    return result


class RealtimeMonitor:
    """Background thread for live packet capture and flow analysis."""

    def __init__(self):
        self.running = False
        self.interface: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._capture_count = 0
        self._last_flow_count = 0

    def start(self, interface: str) -> None:
        """Start monitoring in background thread."""
        with self._lock:
            if self.running:
                return
            self.running = True
            self.interface = interface or None
            self._thread = threading.Thread(
                target=self._run,
                args=(interface,),
                daemon=True,
            )
            self._thread.start()
            logger.info(f"Realtime monitor started on interface: {interface or 'default'}")

    def stop(self) -> None:
        """Stop monitoring."""
        with self._lock:
            self.running = False
        logger.info("Realtime monitor stopped")

    def _run(self, interface: str) -> None:
        """Main loop: capture -> build flows -> classify -> insert."""
        while self.running:
            try:
                packets = capture_packets(interface, duration=5)
                if not packets:
                    continue

                flows_raw = build_flows_from_packets(packets)
                if not flows_raw:
                    continue

                from app.services.decision_service import decision_engine
                from app import db

                enriched = decision_engine.classify_flows(flows_raw)
                if not enriched:
                    continue

                self._capture_count += 1
                self._last_flow_count = len(enriched)

                for f in enriched:
                    f["monitor_type"] = "active"
                    f["analysis_id"] = None
                    f["upload_filename"] = "realtime"
                    f["id"] = str(uuid.uuid4())[:8]
                    f["timestamp"] = datetime.utcnow().isoformat() + "Z"

                db.insert_flows(enriched, monitor_type="active")
                logger.debug(f"Inserted {len(enriched)} active flows from {len(packets)} packets")

            except Exception as e:
                logger.error(f"Realtime monitor loop error: {e}", exc_info=True)
                # Continue to next iteration

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "running": self.running,
                "interface": self.interface if self.interface else "lo (default)",
                "capture_count": self._capture_count,
                "last_flow_count": self._last_flow_count,
                "capture_error": _last_capture_error,
            }


# Global singleton
realtime_monitor = RealtimeMonitor()
