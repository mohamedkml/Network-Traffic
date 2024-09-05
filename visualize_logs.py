import matplotlib.pyplot as plt
import datetime

# Lire le fichier de log
log_file_path = 'suspicious_packets.log'
with open(log_file_path, 'r') as file:
    lines = file.readlines()

# Extraire les informations des logs
timestamps = []
alerts = []

for line in lines:
    if "Possible port scan detected from" in line:
        parts = line.split(" - ")
        timestamp_str = parts[0]
        alert = parts[1].strip()

        timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        timestamps.append(timestamp)
        alerts.append(alert)

# Compter les occurrences d'alertes par minute
time_buckets = {}
for timestamp in timestamps:
    bucket = timestamp.replace(second=0, microsecond=0)
    if bucket not in time_buckets:
        time_buckets[bucket] = 1
    else:
        time_buckets[bucket] += 1

# Trier les buckets par heure
sorted_buckets = sorted(time_buckets.items())

# Séparer les clés (timestamps) et les valeurs (occurrences)
times = [bucket[0] for bucket in sorted_buckets]
counts = [bucket[1] for bucket in sorted_buckets]

# Créer le graphique
plt.figure(figsize=(10, 5))
plt.plot(times, counts, marker='o', linestyle='-',c='hotpink')
plt.xlabel('Time',c='hotpink',fontweight='bold')
plt.ylabel('Number of Alerts',c='hotpink',weight='bold')
plt.title('Number of Port Scan Alerts Over Time',fontweight='bold')
plt.grid(True)
plt.tight_layout()

# Afficher le graphique
plt.show()

