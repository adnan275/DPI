#!/usr/bin/env python3
import sys

from dpi.dpi_engine import DPIEngine, DPIConfig


USAGE = """
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                            ║
║               Deep Packet Inspection System                   ║
╚══════════════════════════════════════════════════════════════╝

Usage: {program} <input.pcap> <output.pcap> [options]

Arguments:
  input.pcap     Input PCAP file (captured user traffic)
  output.pcap    Output PCAP file (filtered traffic to internet)

Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (e.g., YouTube, Facebook)
  --block-domain <dom>   Block domain (supports wildcards: *.facebook.com)
  --rules <file>         Load blocking rules from file
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --verbose              Enable verbose output

Examples:
  {program} capture.pcap filtered.pcap
  {program} capture.pcap filtered.pcap --block-app YouTube
  {program} capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  {program} capture.pcap filtered.pcap --rules blocking_rules.txt

Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub

Architecture:
  ┌─────────────┐
  │ PCAP Reader │  Reads packets from input file
  └──────┬──────┘
         │ hash(5-tuple) % num_lbs
         ▼
  ┌──────┴──────┐
  │ Load Balancer │  LB threads distribute to FPs
  └──┬───────┬──┘
     │       │  hash(5-tuple) % fps_per_lb
     ▼       ▼
  ┌──┴──┐ ┌──┴──┐
  │ FP0 │ │ FP1 │  FP threads: DPI, classification, blocking
  └──┬──┘ └──┬──┘
     │       │
     ▼       ▼
  ┌──┴───────┴──┐
  │ Output Writer │  Writes forwarded packets to output
  └─────────────┘
"""


def main():
    if len(sys.argv) < 3:
        print(USAGE.format(program=sys.argv[0]))
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    config = DPIConfig(num_load_balancers=2, fps_per_lb=2)
    block_ips = []
    block_apps = []
    block_domains = []
    rules_file = ""

    args = sys.argv[3:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--block-ip" and i + 1 < len(args):
            i += 1
            block_ips.append(args[i])
        elif arg == "--block-app" and i + 1 < len(args):
            i += 1
            block_apps.append(args[i])
        elif arg == "--block-domain" and i + 1 < len(args):
            i += 1
            block_domains.append(args[i])
        elif arg == "--rules" and i + 1 < len(args):
            i += 1
            rules_file = args[i]
        elif arg == "--lbs" and i + 1 < len(args):
            i += 1
            config.num_load_balancers = int(args[i])
        elif arg == "--fps" and i + 1 < len(args):
            i += 1
            config.fps_per_lb = int(args[i])
        elif arg == "--verbose":
            config.verbose = True
        elif arg in ("--help", "-h"):
            print(USAGE.format(program=sys.argv[0]))
            sys.exit(0)
        i += 1

    engine = DPIEngine(config)

    if not engine.initialize():
        print("Failed to initialize DPI engine", file=sys.stderr)
        sys.exit(1)

    if rules_file:
        engine.load_rules(rules_file)

    for ip in block_ips:
        engine.block_ip(ip)

    for app in block_apps:
        engine.block_app(app)

    for domain in block_domains:
        engine.block_domain(domain)

    if not engine.process_file(input_file, output_file):
        print("Failed to process file", file=sys.stderr)
        sys.exit(1)

    print("\nProcessing complete!")
    print(f"Output written to: {output_file}")


if __name__ == "__main__":
    main()
