import sqlite3
import json
from datetime import datetime
from src.config import Config

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(Config.DB_FILE, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._create_tables()

    def _create_tables(self):
        # جدول الهجمات
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                attacker_ip TEXT,
                target_port INTEGER,
                attack_type TEXT,
                mitre_id TEXT,
                confidence REAL,
                redirected BOOLEAN,
                honeypot_type TEXT,
                threat_intel TEXT
            )
        ''')
        # جدول الجلسات
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attacker_ip TEXT,
                start_time TEXT,
                end_time TEXT,
                packet_count INTEGER,
                summary TEXT
            )
        ''')
        # جدول التسلسل الزمني
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                timestamp TEXT,
                event_type TEXT,
                details TEXT
            )
        ''')
        # 🆕 جدول البصمات والملفات الشخصية للمهاجمين
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attacker_ip TEXT UNIQUE,
                fingerprint TEXT,
                browser_data TEXT,
                behavior_summary TEXT,
                first_seen TEXT,
                last_seen TEXT,
                attack_count INTEGER,
                risk_score REAL
            )
        ''')
        self.conn.commit()

    def log_attack(self, attacker_ip, target_port, attack_type, mitre_id, confidence, redirected, honeypot_type, threat_intel):
        self.cursor.execute('''
            INSERT INTO attacks (timestamp, attacker_ip, target_port, attack_type, mitre_id, confidence, redirected, honeypot_type, threat_intel)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (datetime.now().isoformat(), attacker_ip, target_port, attack_type, mitre_id, confidence, redirected, honeypot_type, json.dumps(threat_intel)))
        self.conn.commit()
        return self.cursor.lastrowid

    def save_profile(self, ip, fingerprint, browser_data, behavior_summary, risk_score):
        now = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO attacker_profiles (attacker_ip, fingerprint, browser_data, behavior_summary, first_seen, last_seen, attack_count, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(attacker_ip) DO UPDATE SET
                fingerprint = excluded.fingerprint,
                browser_data = excluded.browser_data,
                behavior_summary = excluded.behavior_summary,
                last_seen = excluded.last_seen,
                attack_count = attack_count + 1,
                risk_score = excluded.risk_score
        ''', (ip, json.dumps(fingerprint), json.dumps(browser_data), json.dumps(behavior_summary), now, now, risk_score))
        self.conn.commit()

    def get_profile(self, ip):
        self.cursor.execute('SELECT * FROM attacker_profiles WHERE attacker_ip = ?', (ip,))
        return self.cursor.fetchone()

    def get_all_profiles(self):
        self.cursor.execute('SELECT attacker_ip, fingerprint, browser_data, attack_count, risk_score FROM attacker_profiles ORDER BY risk_score DESC')
        return self.cursor.fetchall()

    def create_session(self, attacker_ip):
        self.cursor.execute('INSERT INTO sessions (attacker_ip, start_time, packet_count) VALUES (?, ?, 0)', (attacker_ip, datetime.now().isoformat()))
        self.conn.commit()
        return self.cursor.lastrowid

    def add_timeline_event(self, session_id, event_type, details):
        self.cursor.execute('INSERT INTO timeline (session_id, timestamp, event_type, details) VALUES (?, ?, ?, ?)',
                           (session_id, datetime.now().isoformat(), event_type, json.dumps(details)))
        self.conn.commit()

    def get_attacks(self, limit=100):
        self.cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?', (limit,))
        return self.cursor.fetchall()

    def get_stats(self):
        self.cursor.execute('SELECT COUNT(*) FROM attacks'); total = self.cursor.fetchone()[0]
        self.cursor.execute('SELECT COUNT(*) FROM attacks WHERE redirected = 1'); redirected = self.cursor.fetchone()[0]
        self.cursor.execute('SELECT COUNT(DISTINCT attacker_ip) FROM attacks'); unique = self.cursor.fetchone()[0]
        return {'total_attacks': total, 'redirected': redirected, 'unique_ips': unique}
