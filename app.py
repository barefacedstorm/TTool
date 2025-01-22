from flask import Flask, request, jsonify, render_template
from flaskwebgui import FlaskUI
from scapy.all import IP, UDP, sr1, ICMP
import requests
import socket
import time

app = Flask(__name__)

# Function to get geolocation and ASN information for an IP address
def get_geolocation_and_asn(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            geolocation = f"{data['city']}, {data['regionName']}, {data['country']}"
            asn = data.get('as')
            org_name = data.get('org', 'Organization not available')
            return geolocation, asn if asn else org_name
        else:
            return "Geolocation not available", "Organization not available"
    except Exception as e:
        return f"Error: {e}", "Organization not available"

# Route to render the front-end HTML page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle traceroute logic
@app.route('/traceroute', methods=['POST'])
def traceroute():
    try:
        # Parse JSON data from the request
        data = request.json
        destination = data.get('destination')
        
        # Ensure max_hops and timeout are integers with defaults
        max_hops = int(data.get('max_hops', 30))
        timeout = int(data.get('timeout', 3))

        # Resolve the destination hostname to an IP address
        try:
            destination_ip = socket.gethostbyname(destination)
        except socket.gaierror:
            return jsonify({"error": "Invalid hostname or IP"}), 400

        ttl = 1
        port = 33434  # Default port used for traceroute (UDP)
        result = []

        # Perform traceroute logic using Scapy
        while ttl <= max_hops:
            ip_packet = IP(dst=destination_ip, ttl=ttl)
            udp_packet = UDP(dport=port)
            packet = ip_packet / udp_packet

            start_time = time.perf_counter()
            reply = sr1(packet, timeout=timeout, verbose=0)
            end_time = time.perf_counter()

            latency = round((end_time - start_time) * 1000, 2)

            if reply is None:
                result.append({
                    "hop": ttl,
                    "ip": "*",
                    "latency": "ICMP blocked",
                    "geolocation": "Request timed out",
                    "asn_or_org": "Organization not available"
                })
            elif reply.type == 3:  # Destination reached
                geolocation, asn_or_org = get_geolocation_and_asn(reply.src)
                result.append({
                    "hop": ttl,
                    "ip": reply.src,
                    "latency": f"{latency} ms",
                    "geolocation": geolocation,
                    "asn_or_org": asn_or_org
                })
                break
            else:
                geolocation, asn_or_org = get_geolocation_and_asn(reply.src)
                result.append({
                    "hop": ttl,
                    "ip": reply.src,
                    "latency": f"{latency} ms",
                    "geolocation": geolocation,
                    "asn_or_org": asn_or_org
                })

            ttl += 1

        return jsonify(result)

    except Exception as e:
        # Handle unexpected errors gracefully and log them for debugging
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


if __name__ == "__main__":
    FlaskUI(app=app, server="flask", width=1200, height=800).run()
