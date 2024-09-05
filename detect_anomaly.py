import logging
from scapy.all import sniff, IP, TCP
import smtplib
from email.mime.text import MIMEText
import os

# Définir le chemin absolu pour le fichier de log
log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'suspicious_packets.log')

logging.basicConfig(filename='suspicious_packets.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

connection_counter = {}

# Fonction pour écrire dans le fichier CSV

def send_alert(message):
    msg = MIMEText(message)
    msg['Subject'] = 'Network Alert'
    msg['From'] = 'kamalmed2@gmail.com'
    msg['To'] = 'kamalmed2@gmail.com'

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login('kamalmed2@gmail.com', 'ysum lwdr hnah vvmm')
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

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
            logging.info(f"Packet: {packet.summary()}")  # Journaliser le paquet suspect
            logging.info(alert_msg)  # Journaliser l'alerte
            send_alert(alert_msg)

# Journaliser chaque paquet traité (pour débogage)
    logging.debug(f"Processed packet: {packet.summary()}")

# Journaliser le début de la capture
logging.info("Starting packet capture")
sniff(prn=detect_port_scan, store=0)
