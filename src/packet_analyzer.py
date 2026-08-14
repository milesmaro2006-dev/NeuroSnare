import numpy as np
from collections import defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw
from src.config import Config

class PacketAnalyzer:
    def __init__(self):
        self.connection_history = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.attack_patterns = {
            'sql_injection': ['select', 'union', 'insert', 'delete', 'drop', '--', ';'],
            'cmd_injection': ['|', '&', ';', '`', '$()', '||', '&&'],
            'path_traversal': ['../', '..\\', '%2e%2e', '%2f']
        }

    def extract_features(self, packet):
        features = []
        if IP in packet:
            features.extend([len(packet), packet[IP].ttl, packet[IP].len, packet[IP].id, packet[IP].flags])
            if TCP in packet:
                features.extend([packet[TCP].sport, packet[TCP].dport, packet[TCP].seq, packet[TCP].ack, packet[TCP].flags, packet[TCP].window, len(packet[TCP].options) if packet[TCP].options else 0])
                if Raw in packet:
                    payload = packet[Raw].load
                    features.extend([len(payload), self._count_patterns(payload, 'sql_injection'), self._count_patterns(payload, 'cmd_injection'), self._count_patterns(payload, 'path_traversal')])
                else: features.extend([0,0,0,0])
            elif UDP in packet:
                features.extend([packet[UDP].sport, packet[UDP].dport, packet[UDP].len, 0,0,0,0,0,0,0,0])
            elif ICMP in packet:
                features.extend([packet[ICMP].type, packet[ICMP].code, packet[ICMP].id, packet[ICMP].seq, 0,0,0,0,0,0,0])
            if Raw in packet: features.append(1)
            else: features.append(0)
        else: features = [0]*25
        while len(features) < 25: features.append(0)
        return features[:25]

    def _count_patterns(self, payload, pattern_type):
        try:
            text = payload.decode('utf-8', errors='ignore').lower()
            return sum(text.count(p) for p in self.attack_patterns.get(pattern_type, []))
        except: return 0

    def detect_port_scan(self, src_ip, dst_port):
        self.port_scan_tracker[src_ip].add(dst_port)
        return len(self.port_scan_tracker[src_ip]) > Config.PORT_SCAN_THRESHOLD

    def detect_connection_rate(self, src_ip):
        now = datetime.now()
        self.connection_history[src_ip] = [t for t in self.connection_history[src_ip] if (now - t).seconds < 60]
        self.connection_history[src_ip].append(now)
        return len(self.connection_history[src_ip]) > Config.CONNECTION_RATE_THRESHOLD

    def check_suspicious_flags(self, packet):
        if TCP in packet:
            f = packet[TCP].flags
            return f in [0x02, 0x01, 0x03, 0x3F]
        return False

    def get_attack_pattern(self, packet):
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                if any(p in payload for p in self.attack_patterns['sql_injection']): return 'SQL_Injection'
                if any(p in payload for p in self.attack_patterns['cmd_injection']): return 'Command_Injection'
                if any(p in payload for p in self.attack_patterns['path_traversal']): return 'Path_Traversal'
                if '<script>' in payload or 'javascript:' in payload: return 'XSS_Attempt'
            except: pass
        return None
