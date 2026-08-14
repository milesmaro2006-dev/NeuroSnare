import os, time, logging, json
from flask import Flask, request, jsonify
from threading import Thread

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, filename='/var/log/honeypot.log')

# 🆕 استقبال بصمة المتصفح من المهاجم
@app.route('/api/fingerprint', methods=['POST'])
def receive_fingerprint():
    try:
        data = request.get_json()
        attacker_ip = request.remote_addr
        logging.info(f"FINGERPRINT from {attacker_ip}: {json.dumps(data)}")
        
        # هنا يمكن إرسالها للمحرك الرئيسي عبر API (اختياري)
        # requests.post('http://<neurosnare_ip>:5000/api/update_fingerprint', json={'ip': attacker_ip, 'data': data})
        
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        logging.error(f"FP error: {e}")
        return jsonify({'status': 'error'}), 500

# بدء الخادم
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
