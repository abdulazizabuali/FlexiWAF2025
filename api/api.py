from flask import Flask, request, jsonify
import json
import os
import requests

app = Flask(__name__)

NGINX_API_URL = "http://flexiwaf_nginx:80/update_rules"

@app.route('/api/rate_limit', methods=['POST', 'GET'])
def update_rate_limit():
    if request.method == 'POST':
        try:
            new_config = request.get_json()
            if not isinstance(new_config, dict):
                return jsonify({"error": "Invalid JSON format"}), 400
            
            headers = {"Content-Type": "application/json", "X-Rule-Type": "rate_limit"}
            response = requests.post(NGINX_API_URL, json=new_config, headers=headers)

            if response.status_code == 200:
                return jsonify({"status": "success", "message": "Rate limit updated successfully"})
            else:
                return jsonify({"error": f"Failed to update NGINX rules: {response.text}"}), 500
        
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    elif request.method == 'GET':
        # NGINX needs to expose a read-only endpoint, for now we will assume the file exists for demonstration
        if os.path.exists('/app/nginx/rate_limit_config.json'):
            with open('/app/nginx/rate_limit_config.json', 'r') as f:
                config = json.load(f)
            return jsonify(config)
        else:
            return jsonify({"error": "Rate limit config file not found"}), 404

@app.route('/api/ip_list', methods=['POST', 'GET'])
def update_ip_list():
    if request.method == 'POST':
        try:
            new_config = request.get_json()
            if not isinstance(new_config, dict):
                return jsonify({"error": "Invalid JSON format"}), 400
            
            headers = {"Content-Type": "application/json", "X-Rule-Type": "ip_list"}
            response = requests.post(NGINX_API_URL, json=new_config, headers=headers)

            if response.status_code == 200:
                return jsonify({"status": "success", "message": "IP lists updated successfully"})
            else:
                return jsonify({"error": f"Failed to update NGINX rules: {response.text}"}), 500
        
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    elif request.method == 'GET':
        if os.path.exists('/app/nginx/ip_list.json'):
            with open('/app/nginx/ip_list.json', 'r') as f:
                config = json.load(f)
            return jsonify(config)
        else:
            return jsonify({"error": "IP list config file not found"}), 404

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)