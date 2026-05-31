#!/usr/bin/env python3
"""
NetProbe — A Network Packet Analyzer
=====================================
Author  : [Your Name]
Version : 1.0.0
License : MIT
GitHub  : https://github.com/<your-username>/netprobe

A lightweight, beginner-friendly CLI tool for capturing and
analyzing live network packets using Python and Scapy.
Supports: TCP, UDP, ICMP, ARP, DNS
"""

import argparse
import os
import sys
from datetime import datetime

# ── Third-party ──────────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Ether
except ImportError:
    sys.exit("[ERROR] Scapy not installed. Run:  pip install scapy")

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    print("[WARN] colorama not installed. Output will be plain text.")
    print("       Install with:  pip install colorama\n")

# ── Color mapping per protocol ────────────────────────────────────────────────
PROTO_COLORS = {
    "TCP":  Fore.CYAN    if COLORS else "",
    "UDP":  Fore.YELLOW  if COLORS else "",
    "ICMP": Fore.MAGENTA if COLORS else "",
    "ARP":  Fore.GREEN   if COLORS else "",
    "DNS":  Fore.BLUE    if COLORS else "",
    "OTHER":Fore.WHITE   if COLORS else "",
}
RESET  = Style.RESET_ALL if COLORS else ""
BOLD   = Style.BRIGHT    if COLORS else ""
RED    = Fore.RED        if COLORS else ""
GREEN  = Fore.GREEN      if COLORS else ""

# ── Global state ──────────────────────────────────────────────────────────────
packet_count  = 0
log_file      = None
filter_proto  = None
filter_ip     = None

# ═════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

def color(text, proto="OTHER"):
    return PROTO_COLORS.get(proto, "") + text + RESET


def get_payload_preview(packet, proto):
    """Return first 40 bytes of payload as a hex + ascii preview."""
    try:
        if proto == "TCP" and packet.haslayer(TCP):
            raw = bytes(packet[TCP].payload)
        elif proto == "UDP" and packet.haslayer(UDP):
            raw = bytes(packet[UDP].payload)
        else:
            return "(no payload)"

        if not raw:
            return "(empty)"

        snippet = raw[:40]
        hex_part   = " ".join(f"{b:02x}" for b in snippet)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in snippet)
        return f"{hex_part}  |  {ascii_part}"
    except Exception:
        return "(parse error)"


def get_tcp_flags(flags_int):
    """Decode TCP flags integer into human-readable string."""
    flag_map = [
        (0x001, "FIN"),
        (0x002, "SYN"),
        (0x004, "RST"),
        (0x008, "PSH"),
        (0x010, "ACK"),
        (0x020, "URG"),
        (0x040, "ECE"),
        (0x080, "CWR"),
    ]
    active = [name for bit, name in flag_map if flags_int & bit]
    return "-".join(active) if active else "NONE"


def log(line):
    """Print to terminal and optionally write to log file."""
    print(line)
    if log_file:
        # Strip ANSI escape codes for clean log file
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)
        log_file.write(clean + "\n")


def separator():
    log(BOLD + "─" * 80 + RESET)


# ═════════════════════════════════════════════════════════════════════════════
# PROTOCOL DECODERS
# ═════════════════════════════════════════════════════════════════════════════

def decode_tcp(packet):
    src_ip  = packet[IP].src
    dst_ip  = packet[IP].dst
    src_prt = packet[TCP].sport
    dst_prt = packet[TCP].dport
    flags   = get_tcp_flags(int(packet[TCP].flags))
    seq     = packet[TCP].seq
    ack     = packet[TCP].ack
    payload = get_payload_preview(packet, "TCP")

    log(color(f"[TCP]  {src_ip}:{src_prt}  →  {dst_ip}:{dst_prt}", "TCP"))
    log(f"       Flags: {BOLD}{flags}{RESET}  |  Seq: {seq}  |  Ack: {ack}")
    log(f"       Payload: {payload}")


def decode_udp(packet):
    src_ip  = packet[IP].src
    dst_ip  = packet[IP].dst
    src_prt = packet[UDP].sport
    dst_prt = packet[UDP].dport
    payload = get_payload_preview(packet, "UDP")

    log(color(f"[UDP]  {src_ip}:{src_prt}  →  {dst_ip}:{dst_prt}", "UDP"))
    log(f"       Payload: {payload}")


def decode_icmp(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    icmp_type = packet[ICMP].type
    icmp_code = packet[ICMP].code

    type_names = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request (Ping)",
        11: "Time Exceeded",
    }
    type_str = type_names.get(icmp_type, f"Type {icmp_type}")

    log(color(f"[ICMP] {src_ip}  →  {dst_ip}", "ICMP"))
    log(f"       {type_str}  |  Code: {icmp_code}")


def decode_arp(packet):
    op = "Request" if packet[ARP].op == 1 else "Reply"
    src_ip  = packet[ARP].psrc
    dst_ip  = packet[ARP].pdst
    src_mac = packet[ARP].hwsrc
    dst_mac = packet[ARP].hwdst

    log(color(f"[ARP]  {op}  |  {src_ip} ({src_mac})  →  {dst_ip} ({dst_mac})", "ARP"))


def decode_dns(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet[DNS].qr == 0:          # Query
        try:
            qname = packet[DNS].qd.qname.decode(errors="replace")
        except Exception:
            qname = "(decode error)"
        log(color(f"[DNS]  Query  |  {src_ip}  →  {dst_ip}", "DNS"))
        log(f"       Question: {BOLD}{qname}{RESET}")
    else:                             # Response
        answers = []
        try:
            for i in range(packet[DNS].ancount):
                rr = packet[DNS].an[i]
                if hasattr(rr, "rdata"):
                    answers.append(str(rr.rdata))
        except Exception:
            answers = ["(parse error)"]
        log(color(f"[DNS]  Response  |  {src_ip}  →  {dst_ip}", "DNS"))
        log(f"       Answers: {', '.join(answers) if answers else 'none'}")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN PACKET HANDLER
# ═════════════════════════════════════════════════════════════════════════════

def process_packet(packet):
    global packet_count, filter_proto, filter_ip

    # ── IP filter ────────────────────────────────────────────────────────────
    if filter_ip and packet.haslayer(IP):
        if filter_ip not in (packet[IP].src, packet[IP].dst):
            return

    # ── Timestamp ────────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # ── Protocol detection & decode ──────────────────────────────────────────
    proto_detected = None

    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS):
        proto_detected = "DNS"
        if filter_proto and filter_proto != "dns":
            return
        separator()
        log(f"{BOLD}[{ts}]  Packet #{packet_count + 1}{RESET}")
        decode_dns(packet)

    elif packet.haslayer(IP) and packet.haslayer(TCP):
        proto_detected = "TCP"
        if filter_proto and filter_proto != "tcp":
            return
        separator()
        log(f"{BOLD}[{ts}]  Packet #{packet_count + 1}{RESET}")
        decode_tcp(packet)

    elif packet.haslayer(IP) and packet.haslayer(UDP):
        proto_detected = "UDP"
        if filter_proto and filter_proto != "udp":
            return
        separator()
        log(f"{BOLD}[{ts}]  Packet #{packet_count + 1}{RESET}")
        decode_udp(packet)

    elif packet.haslayer(IP) and packet.haslayer(ICMP):
        proto_detected = "ICMP"
        if filter_proto and filter_proto != "icmp":
            return
        separator()
        log(f"{BOLD}[{ts}]  Packet #{packet_count + 1}{RESET}")
        decode_icmp(packet)

    elif packet.haslayer(ARP):
        proto_detected = "ARP"
        if filter_proto and filter_proto != "arp":
            return
        separator()
        log(f"{BOLD}[{ts}]  Packet #{packet_count + 1}{RESET}")
        decode_arp(packet)

    else:
        # Unknown / unsupported protocol — skip silently
        return

    packet_count += 1


# ═════════════════════════════════════════════════════════════════════════════
# BANNER & SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

def print_banner(args):
    banner = f"""
{BOLD}{PROTO_COLORS['TCP']}
  _   _      _   ____            _
 | \\ | | ___| |_|  _ \\ _ __ ___| |__   ___
 |  \\| |/ _ \\ __| |_) | '__/ _ \\ '_ \\ / _ \\
 | |\\  |  __/ |_|  __/| | |  __/ |_) |  __/
 |_| \\_|\\___|\\__|_|   |_|  \\___|_.__/ \\___|
{RESET}
{BOLD}  A Network Packet Analyzer  |  v1.0.0  |  Python + Scapy{RESET}
  {"─" * 55}
  Interface : {BOLD}{args.iface}{RESET}
  Filter    : {BOLD}{args.filter.upper() if args.filter else "ALL PROTOCOLS"}{RESET}
  IP Filter : {BOLD}{args.ip if args.ip else "None"}{RESET}
  Pkt Limit : {BOLD}{args.count if args.count else "Unlimited"}{RESET}
  Logging   : {BOLD}{GREEN + "ON" + RESET if args.log else RED + "OFF" + RESET}
  {"─" * 55}
  Protocols : {color("TCP","TCP")}  {color("UDP","UDP")}  {color("ICMP","ICMP")}  {color("ARP","ARP")}  {color("DNS","DNS")}
  {"─" * 55}
  Press  Ctrl+C  to stop and view session summary.
"""
    print(banner)


def print_summary():
    print(f"""
{BOLD}{"═" * 80}
  SESSION SUMMARY
{"═" * 80}{RESET}
  Total packets captured : {BOLD}{GREEN}{packet_count}{RESET}
  Session ended at       : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  Log file               : {BOLD}{log_file.name if log_file else "Not saved"}{RESET}
{"═" * 80}
""")


# ═════════════════════════════════════════════════════════════════════════════
# CLI ARGUMENT PARSING
# ═════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="NetProbe — Lightweight network packet analyzer for students",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python netprobe.py --iface eth0
  sudo python netprobe.py --iface wlan0 --filter tcp --count 50
  sudo python netprobe.py --iface eth0 --filter dns --log
  sudo python netprobe.py --iface eth0 --ip 192.168.1.5 --log

Supported Protocols:
  tcp   UDP   icmp   arp   dns
        """
    )
    parser.add_argument(
        "--iface", "-i",
        required=True,
        help="Network interface to capture on  (e.g. eth0, wlan0, Ethernet)"
    )
    parser.add_argument(
        "--filter", "-f",
        choices=["tcp", "udp", "icmp", "arp", "dns"],
        default=None,
        help="Capture only this protocol  (default: all)"
    )
    parser.add_argument(
        "--ip",
        default=None,
        help="Capture only packets from/to this IP address"
    )
    parser.add_argument(
        "--count", "-c",
        type=int,
        default=0,
        help="Number of packets to capture  (0 = unlimited)"
    )
    parser.add_argument(
        "--log", "-l",
        action="store_true",
        help="Save session output to a timestamped log file"
    )
    return parser.parse_args()


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    global log_file, filter_proto, filter_ip

    args       = parse_args()
    filter_proto = args.filter
    filter_ip    = args.ip

    # ── Open log file ────────────────────────────────────────────────────────
    if args.log:
        os.makedirs("logs", exist_ok=True)
        log_filename = f"logs/netprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        log_file = open(log_filename, "w", encoding="utf-8")
        log_file.write(f"NetProbe Session Log — {datetime.now()}\n")
        log_file.write(f"Interface: {args.iface}  |  Filter: {args.filter or 'ALL'}\n")
        log_file.write("=" * 80 + "\n")

    print_banner(args)

    try:
        sniff(
            iface=args.iface,
            prn=process_packet,
            count=args.count,
            store=False,       # Don't store packets in memory
        )
    except PermissionError:
        sys.exit(f"\n{RED}[ERROR] Permission denied. Run with sudo (Linux/macOS) or as Administrator (Windows).{RESET}")
    except OSError as e:
        sys.exit(f"\n{RED}[ERROR] Interface '{args.iface}' not found or unavailable.\n{e}{RESET}")
    except KeyboardInterrupt:
        pass                   # Graceful Ctrl+C

    print_summary()

    if log_file:
        log_file.write("\n" + "=" * 80 + "\n")
        log_file.write(f"Total packets: {packet_count}\n")
        log_file.close()
        print(f"{GREEN}[✓] Log saved → {log_file.name}{RESET}")


if __name__ == "__main__":
    main()
