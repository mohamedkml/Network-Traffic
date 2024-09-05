import scapy.all as scapy
from collections import Counter
import os

def analyze_packets(packet_list):
    ip_addresses = []
    for packet in packet_list:
        if scapy.IP in packet:
            ip_addresses.append(packet[scapy.IP].src)
            ip_addresses.append(packet[scapy.IP].dst)
    ip_counter = Counter(ip_addresses)
    print(ip_counter)

# Assurez-vous que le fichier 'wireshark.pcapng' existe dans le répertoire actuel
file_path = "./capture.pcapng/wireshark.pcapng"

# Vérifiez si le fichier existe et les permissions
if not os.path.isfile(file_path):
    print(f"Erreur : Le fichier {file_path} n'existe pas.")
elif not os.access(file_path, os.R_OK):
    print(f"Erreur : Permission de lecture refusée pour le fichier {file_path}.")
else:
    try:
        p = scapy.rdpcap(file_path)
        analyze_packets(p)
    except OSError as e:
        print(f"Erreur lors de la lecture du fichier PCAP: {e}")
    except Exception as e:
        print(f"Une erreur s'est produite: {e}")

