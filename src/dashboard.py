from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from src.database import Database
from src.attacker_profiler import AttackerProfiler
from src.config import Config

app = Flask(__name__, static_folder='../static', template_folder='../templates')
CORS(app)
db = Database()
profiler = AttackerProfiler()

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def stats():
    return jsonify(db.get_stats())

@app.route('/api/attacks')
def attacks():
    return jsonify(db.get_attacks(limit=50))

@app.route('/api/profiles')
def profiles():
    """جميع ملفات المهاجمين"""
    return jsonify(db.get_all_profiles())

@app.route('/api/profile/<ip>')
def profile(ip):
    """ملف مهاجم محدد"""
    data = profiler.get_full_profile(ip)
    if data:
        return jsonify(data)
    return jsonify({'error': 'Not found'}), 404

@app.route('/api/correlate')
def correlate():
    """ربط الـ IPs لنفس المهاجم"""
    return jsonify(profiler.correlate_ips())

def run_dashboard():
    app.run(host='0.0.0.0', port=Config.DASHBOARD_PORT, debug=False)
