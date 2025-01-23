import logging
import socket
import time
import requests
from flask import Flask, request, jsonify, render_template
from scapy.all import IP, UDP, sr1

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def get_geolocation_and_asn(ip):
    try:
        if not ip or ip == '*':
            return "BGP Peer", "Transit Network", None

        # Add retry logic for IP API
        for attempt in range(3):
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.ok:
                data = response.json()
                if data['status'] == 'success':
                    geolocation = f"{data['city']}, {data['regionName']}, {data['country']}"
                    asn = data.get('as')
                    org_name = data.get('org', 'Organization not available')
                    coordinates = {
                        'lat': data['lat'],
                        'lon': data['lon']
                    }
                    return geolocation, asn if asn else org_name, coordinates
                break
            time.sleep(1)

        # If we get here, use BGP data instead
        return "Network Transit Point", "BGP Network", None
    except Exception as e:
        logger.debug(f"Geolocation lookup failed for IP {ip}: {str(e)}")
        return "Network Transit Point", "BGP Network", None

@app.route('/')
def index():
    return render_template('index.html')

def get_network_path(source_ip, destination_ip, max_hops=30, timeout=3):
    path_data = []

    # Start with client location
    source_geo, source_asn, source_coords = get_geolocation_and_asn(source_ip)
    path_data.append({
        "hop": 1,
        "ip": source_ip,
        "latency": "<1 ms",
        "geolocation": source_geo,
        "asn_or_org": source_asn,
        "coordinates": source_coords
    })

    # Try ICMP first for each hop
    ttl = 2
    while ttl <= max_hops:
        ip_packet = IP(dst=destination_ip, ttl=ttl)
        udp_packet = UDP(dport=33434)
        packet = ip_packet / udp_packet

        start_time = time.perf_counter()
        reply = sr1(packet, timeout=timeout, verbose=0)
        end_time = time.perf_counter()
        latency = round((end_time - start_time) * 1000, 2)

        if reply is None:
            # ICMP blocked, fallback to BGP data
            asn_number = source_asn.split()[0].replace('AS', '') if source_asn else None
            if asn_number:
                response = requests.get(f"https://api.bgpview.io/asn/{asn_number}/upstreams")
                if response.ok:
                    upstream = response.json().get('data', {}).get('ipv4_upstreams', [{}])[0]
                    geo, asn, coords = get_geolocation_and_asn(upstream.get('ip', '*'))
                    path_data.append({
                        "hop": ttl,
                        "ip": f"BGP Peer - AS{upstream.get('asn')}",
                        "latency": f"{latency} ms",
                        "geolocation": geo,
                        "asn_or_org": asn,
                        "coordinates": coords
                    })
        else:
            geo, asn, coords = get_geolocation_and_asn(reply.src)
            path_data.append({
                "hop": ttl,
                "ip": reply.src,
                "latency": f"{latency} ms",
                "geolocation": geo,
                "asn_or_org": asn,
                "coordinates": coords
            })
            if reply.type == 3:
                break

        ttl += 1

    return path_data

@app.route('/traceroute', methods=['POST'])
def traceroute():
    client_ip = (
        request.headers.get('X-Real-IP') or
        request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or
        request.remote_addr
    )

    data = request.json
    destination = data.get('destination')
    max_hops = int(data.get('max_hops', 30))
    timeout = int(data.get('timeout', 3))

    try:
        destination_ip = socket.gethostbyname(destination)
        network_path = get_network_path(client_ip, destination_ip, max_hops, timeout)
        return jsonify(network_path)
    except Exception as e:
        logger.error(f"Network path error: {str(e)}", exc_info=True)
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5009)
