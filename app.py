from flask import Flask, render_template, jsonify
import threading
from scapy.all import sniff, IP, TCP

app = Flask(__name__)

alerts = []

def send_alert(message):
    # Ajoutez votre logique pour envoyer des alertes ici
    alerts.append(message)

def detect_port_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        ip_src = packet[IP].src
        if ip_src not in connection_counter:
            connection_counter[ip_src] = 1
        else:
            connection_counter[ip_src] += 1

        if connection_counter[ip_src] > 10:  # Ajustez le seuil selon vos besoins
            alert_msg = f"Possible port scan detected from {ip_src}"
            print(alert_msg)
            send_alert(alert_msg)

connection_counter = {}

def start_sniffing():
    sniff(prn=detect_port_scan, store=0)

sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

@app.route('/alerts')
def show_alerts():
    return render_template('alerts.html')

@app.route('/api/alerts')
def get_alerts():
    return jsonify(alerts)

if __name__ == '__main__':
    app.run(debug=True)
