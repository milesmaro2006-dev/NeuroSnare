import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from src.packet_analyzer import PacketAnalyzer
from src.ai_engine import ai_engine
from src.responder import TacticalResponder
from src.mitre_mapper import MITREMapper
from src.threat_intel import ThreatIntel
from src.database import Database
from src.attacker_profiler import AttackerProfiler
from src.logger import logger
from src.config import Config

class NetworkSniffer:
    def __init__(self):
        self.analyzer = PacketAnalyzer()
        self.responder = TacticalResponder()
        self.mitre = MITREMapper()
        self.threat = ThreatIntel()
        self.db = Database()
        self.profiler = AttackerProfiler()  # 🆕
        self.running = False
        self.packet_count = 0
        self.last_attack_time = {}
        self.sessions = {}

    def start_sniffing(self, interface):
        self.running = True
        logger.log_system_event('START', f'Sniffing on {interface}')
        sniff(iface=interface, prn=self._packet_handler, store=False)

    def _packet_handler(self, packet):
        if not self.running: return
        self.packet_count += 1
        if IP in packet:
            src = packet[IP].src
            features = self.analyzer.extract_features(packet)
            result = ai_engine.predict(features)

            # 🆕 تحديث البصمة التقنية للمهاجم (TTL, Window)
            ttl = packet[IP].ttl
            tcp_window = 0
            user_agent = ''
            if TCP in packet:
                tcp_window = packet[TCP].window
                # محاولة استخراج User-Agent من الـ payload (لو HTTP)
                if Raw in packet:
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if 'User-Agent' in payload:
                            lines = payload.split('\n')
                            for line in lines:
                                if 'User-Agent:' in line:
                                    user_agent = line.split('User-Agent:')[1].strip()
                                    break
                    except: pass
            self.profiler.update_network_fingerprint(src, ttl, tcp_window, user_agent)

            is_port_scan = self.analyzer.detect_port_scan(src, packet[TCP].dport) if TCP in packet else False
            is_high_rate = self.analyzer.detect_connection_rate(src)
            is_suspicious = self.analyzer.check_suspicious_flags(packet)
            attack_pattern = self.analyzer.get_attack_pattern(packet)

            if result['is_attack'] or is_port_scan or is_high_rate or is_suspicious:
                target_port = 0
                if TCP in packet: target_port = packet[TCP].dport
                elif UDP in packet: target_port = packet[UDP].dport

                atk_type = attack_pattern if attack_pattern else self._determine_type(packet, result)
                mitre_id = self.mitre.get_mitre_id(atk_type)
                threat_data = self.threat.check_ip(src)

                # 🆕 تسجيل الهجوم في ملف المهاجم
                risk_score = self.profiler.record_attack(src, atk_type, target_port, result['confidence'])

                redirected, h_type = self.responder.route_to_honeypot(src, target_port)

                self.db.log_attack(src, target_port, atk_type, mitre_id, result['confidence'], redirected, h_type, threat_data)

                if src not in self.sessions:
                    self.sessions[src] = self.db.create_session(src)
                self.db.add_timeline_event(self.sessions[src], 'ATTACK_DETECTED', {
                    'type': atk_type, 
                    'port': target_port,
                    'mitre': mitre_id,
                    'risk_score': risk_score
                })

                print(f"\n[!!!] {atk_type} from {src} (MITRE: {mitre_id})")
                print(f"    Risk Score: {risk_score:.2%}")
                print(f"    Redirected to: {h_type}")

    def _determine_type(self, packet, result):
        if TCP in packet:
            flags = packet[TCP].flags
            if flags == 0x02: return 'SYN_Flood'
            if flags == 0x01: return 'FIN_Scan'
            if flags == 0x03: return 'SYN_FIN_Scan'
            if flags == 0x3F: return 'XMAS_Scan'
            if packet[TCP].dport in [22,23,21,3389]: return 'Brute_Force_Attempt'
            if packet[TCP].dport in [80,443,8080]: return 'Web_Attack'
            return 'Port_Scan' if result['is_attack'] else 'TCP_Anomaly'
        if UDP in packet: return 'UDP_Flood'
        if ICMP in packet: return 'ICMP_Echo_Attack'
        return 'Unknown_Attack'

    def stop_sniffing(self):
        self.running = False
        self.responder.cleanup()

sniffer = NetworkSniffer()
