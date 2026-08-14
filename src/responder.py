import subprocess, time, re
from src.config import Config
from src.logger import logger

class TacticalResponder:
    def __init__(self):
        self.redirected_ips = {}; self.iptables_rules = []; self._setup_chain()
    def _setup_chain(self):
        try:
            subprocess.run(f"iptables -t {Config.IPTABLES_TABLE} -N {Config.IPTABLES_CHAIN}".split(), check=False)
            subprocess.run(f"iptables -t {Config.IPTABLES_TABLE} -A PREROUTING -j {Config.IPTABLES_CHAIN}".split(), check=False)
        except: pass
    def route_to_honeypot(self, attacker_ip, target_port):
        honeypot_type = 'web'
        if target_port in [22]: honeypot_type = 'ssh'
        elif target_port in [80, 443, 8080]: honeypot_type = 'web'
        elif target_port in [21]: honeypot_type = 'ftp'
        elif target_port in [445, 139]: honeypot_type = 'smb'
        honeypot_ip = Config.HONEYPOT_IPS.get(honeypot_type, Config.HONEYPOT_IPS['web'])
        if attacker_ip in self.redirected_ips: return True, honeypot_type
        rule = f"iptables -t {Config.IPTABLES_TABLE} -A {Config.IPTABLES_CHAIN} -s {attacker_ip} -j DNAT --to-destination {honeypot_ip}"
        try:
            subprocess.run(rule.split(), check=True)
            self.redirected_ips[attacker_ip] = {'time': time.time(), 'honeypot': honeypot_ip, 'type': honeypot_type}
            self.iptables_rules.append(rule); return True, honeypot_type
        except Exception as e: logger.log_error('ROUTE', str(e)); return False, None
    def block_attacker(self, attacker_ip):
        try: subprocess.run(f"iptables -t {Config.IPTABLES_TABLE} -A {Config.IPTABLES_CHAIN} -s {attacker_ip} -j DROP".split(), check=True); return True
        except: return False
    def cleanup(self):
        for rule in self.iptables_rules: subprocess.run(rule.replace('-A', '-D').split(), check=False)
        subprocess.run(f"iptables -t {Config.IPTABLES_TABLE} -F {Config.IPTABLES_CHAIN}".split(), check=False)
        subprocess.run(f"iptables -t {Config.IPTABLES_TABLE} -X {Config.IPTABLES_CHAIN}".split(), check=False)
        self.iptables_rules = []; self.redirected_ips = {}
