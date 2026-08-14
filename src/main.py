#!/usr/bin/env python3
import sys, signal, threading, time
from src.sniffer import sniffer
from src.ai_engine import ai_engine
from src.dashboard import run_dashboard
from src.logger import logger
from src.config import Config

def signal_handler(sig, frame):
    print("\n[!] Shutting down...")
    sniffer.stop_sniffing()
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    print("""
╔═══════════════════════════════════════════════════╗
║   🛡️ NeuroSnare v3.0 - Professional Edition    ║
║   AI Detection | Multi-Honeypot | Profiling      ║
╚═══════════════════════════════════════════════════╝
    """)
    ai_engine.train_model()
    threading.Thread(target=sniffer.start_sniffing, args=(Config.NETWORK_INTERFACE,), daemon=True).start()
    threading.Thread(target=run_dashboard, daemon=True).start()
    print(f"[+] Dashboard: http://localhost:{Config.DASHBOARD_PORT}")
    while True: time.sleep(1)

if __name__ == '__main__':
    main()
