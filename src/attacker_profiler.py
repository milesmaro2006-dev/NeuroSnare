"""
هذا الملف مسؤول عن بناء ملف كامل عن المهاجم
يجمع بين: البصمة التقنية، السلوك، بيانات المتصفح، ويربط كل ذلك ببعضه
"""
import json
from datetime import datetime
from collections import defaultdict
from src.database import Database
from src.logger import logger
from src.threat_intel import ThreatIntel

class AttackerProfiler:
    def __init__(self):
        self.db = Database()
        self.threat = ThreatIntel()
        self.behavior_cache = defaultdict(list)  # تخزين مؤقت للسلوك
        self.fingerprint_cache = {}  # تخزين مؤقت للبصمة

    def record_attack(self, attacker_ip, attack_type, target_port, confidence):
        """تسجيل هجوم جديد في ملف المهاجم"""
        # 1. تحديث السلوك
        self.behavior_cache[attacker_ip].append({
            'timestamp': datetime.now().isoformat(),
            'type': attack_type,
            'port': target_port,
            'confidence': confidence
        })
        
        # 2. تحليل السمعة
        threat_data = self.threat.check_ip(attacker_ip)
        
        # 3. حساب درجة المخاطرة
        risk_score = self._calculate_risk_score(attacker_ip, threat_data)
        
        # 4. تحديث قاعدة البيانات
        self.db.save_profile(
            ip=attacker_ip,
            fingerprint=self.fingerprint_cache.get(attacker_ip, {}),
            browser_data={},  # سيتم تحديثها من الـ Honeypot
            behavior_summary=self._generate_behavior_summary(attacker_ip),
            risk_score=risk_score
        )
        
        logger.log_system_event('PROFILE_UPDATED', f'Updated profile for {attacker_ip} (Risk: {risk_score})')
        return risk_score

    def update_browser_fingerprint(self, ip, browser_data):
        """تحديث بصمة المتصفح (تُستقبل من الـ Honeypot)"""
        if ip not in self.fingerprint_cache:
            self.fingerprint_cache[ip] = {}
        self.fingerprint_cache[ip]['browser'] = browser_data
        
        # تحديث في قاعدة البيانات
        current = self.db.get_profile(ip)
        if current:
            old_fp = json.loads(current[2]) if current[2] else {}
            old_fp['browser'] = browser_data
            self.db.save_profile(
                ip=ip,
                fingerprint=old_fp,
                browser_data=browser_data,
                behavior_summary=self._generate_behavior_summary(ip),
                risk_score=current[6] if len(current) > 6 else 0.5
            )

    def update_network_fingerprint(self, ip, ttl, tcp_window, user_agent):
        """تحديث البصمة التقنية (من الحزم)"""
        if ip not in self.fingerprint_cache:
            self.fingerprint_cache[ip] = {}
        self.fingerprint_cache[ip]['network'] = {
            'ttl': ttl,
            'tcp_window': tcp_window,
            'user_agent': user_agent
        }

    def _generate_behavior_summary(self, ip):
        """تلخيص سلوك المهاجم"""
        attacks = self.behavior_cache.get(ip, [])
        if not attacks:
            return "No attacks recorded"
        
        # تحليل الأنماط
        types = {}
        ports = set()
        for a in attacks:
            types[a['type']] = types.get(a['type'], 0) + 1
            ports.add(a['port'])
        
        most_common = max(types, key=types.get) if types else "Unknown"
        summary = {
            'total_attacks': len(attacks),
            'attack_types': types,
            'target_ports': list(ports),
            'most_common_attack': most_common,
            'first_seen': attacks[0]['timestamp'],
            'last_seen': attacks[-1]['timestamp']
        }
        return summary

    def _calculate_risk_score(self, ip, threat_data):
        """حساب درجة المخاطرة (0-1)"""
        score = 0.0
        
        # 1. عدد الهجمات
        attack_count = len(self.behavior_cache.get(ip, []))
        if attack_count > 10:
            score += 0.3
        elif attack_count > 5:
            score += 0.2
        
        # 2. سمعة Threat Intel
        if 'abuseipdb' in threat_data.get('sources', {}):
            abuse_score = threat_data['sources']['abuseipdb'].get('score', 0)
            if abuse_score > 80:
                score += 0.3
            elif abuse_score > 50:
                score += 0.2
        
        if 'virustotal' in threat_data.get('sources', {}):
            vt_mal = threat_data['sources']['virustotal'].get('malicious', 0)
            if vt_mal > 5:
                score += 0.2
        
        # 3. تنوع الهجمات (مهاجم متقدم)
        types = set()
        for a in self.behavior_cache.get(ip, []):
            types.add(a['type'])
        if len(types) > 3:
            score += 0.2
        
        return min(score, 1.0)

    def get_full_profile(self, ip):
        """الحصول على ملف كامل للمهاجم"""
        db_profile = self.db.get_profile(ip)
        if not db_profile:
            return None
        
        return {
            'ip': ip,
            'fingerprint': json.loads(db_profile[2]) if db_profile[2] else {},
            'browser_data': json.loads(db_profile[3]) if db_profile[3] else {},
            'behavior_summary': json.loads(db_profile[4]) if db_profile[4] else {},
            'first_seen': db_profile[5],
            'last_seen': db_profile[6],
            'attack_count': db_profile[7],
            'risk_score': db_profile[8]
        }

    def correlate_ips(self):
        """ربط IPs لنفس المهاجم (حتى لو غير VPN) باستخدام البصمة"""
        profiles = self.db.get_all_profiles()
        correlated = {}
        
        for ip, fp_json, browser_json, count, risk in profiles:
            if not fp_json:
                continue
            fp = json.loads(fp_json)
            
            # استخدام Canvas Fingerprint كمفتاح (الأقوى)
            canvas_fp = fp.get('browser', {}).get('canvas', '')
            if canvas_fp and canvas_fp != 'canvas_error':
                if canvas_fp not in correlated:
                    correlated[canvas_fp] = []
                correlated[canvas_fp].append({
                    'ip': ip,
                    'risk': risk,
                    'attack_count': count
                })
        
        # تصفية المجموعات التي لها أكثر من IP (نفس المهاجم)
        result = []
        for fp, ips in correlated.items():
            if len(ips) > 1:
                result.append({
                    'canvas_fingerprint': fp,
                    'ips': ips,
                    'total_attacks': sum(i['attack_count'] for i in ips),
                    'max_risk': max(i['risk'] for i in ips)
                })
        
        return result
