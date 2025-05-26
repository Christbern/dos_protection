import requests
import time

# Ce fichier est à usage de test pour un client (client1) qui détient une ip ou un domaine (local selon les spécifications reçues) précis
client_id = "client1"
url = f"http://127.0.0.1:8000/monitor/check/?client_id={client_id}"
total_requests = 200
delay_between_requests = 1

for i in range(total_requests):
    try:
        response = requests.get(url)
        print(f"{i+1}: {response.status_code} - {response.json()}")
        if response.status_code == 429:
            print("Bloqué !")
            break
        time.sleep(delay_between_requests)
    except Exception as e:
        print(f"Erreur : {e}")
        break
