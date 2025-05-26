

from rest_framework.decorators import api_view
from rest_framework.response import Response
from .utils import redis_client
from .models import Client
import time

from django.shortcuts import render
import requests
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.urls import reverse

# les clés de RECAPTCHA obtenable via le lien : https://www.google.com/recaptcha/admin/create
RECAPTCHA_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"  # clé secrète de test

THRESHOLDS = {
    1: 10,         # max 10 req en 1 sec
    10: 50,        # max 50 req en 10 sec
    60: 300,       # max 300 req en 1 min
    3600: 2000     # max 2000 req en 1 h
}

@api_view(['GET'])
def register_request(request):
    client_id = request.GET.get("client_id")
    if not client_id:
        return Response({"error": "client_id manquant"}, status=400)

    try:
        client = Client.objects.get(identifier=client_id)
    except Client.DoesNotExist:
        return Response({"error": "Client inconnu"}, status=404)

    key_base = client.ip_address or client.domain
    if not key_base:
        return Response({"error": "IP ou domaine manquant dans le client"}, status=400)

    now = int(time.time())
    anomaly_detected = False
    counters = {}

    for window, threshold in THRESHOLDS.items(): # Contrôle du traffic en fonction des plages estimées vulnérables
        time_bucket = now - (now % window)
        key = f"traffic:{key_base}:{window}:{time_bucket}"
        
        redis_client.incr(key)
        redis_client.expire(key, window)

        count = int(redis_client.get(key) or 0)
        counters[window] = count

        if count > threshold:
            anomaly_detected = True

    if anomaly_detected:
        recaptcha_url = request.build_absolute_uri(
            reverse("recaptcha") + f"?client_id={client_id}"
        )
        return Response({
            "status": "blocked",
            "message": "Trafic anormal détecté. Validation reCAPTCHA requise.",
            "recaptcha_url": recaptcha_url,
            "counters": counters
        }, status=429)

    return Response({
        "status": "ok",
        "client": client.identifier,
        "counters": counters
    })


@csrf_exempt
@api_view(['GET', 'POST'])
def recaptcha_verification(request):
    if request.method == "GET":
        client_id = request.GET.get("client_id")
        return render(request, "monitor/recaptcha_form.html", {"client_id": client_id})

    elif request.method == "POST":
        recaptcha_response = request.POST.get('g-recaptcha-response')
        client_id = request.POST.get("client_id")

        if not client_id or not recaptcha_response:
            return Response({"error": "Données manquantes"}, status=400)

        # Vérifier le reCAPTCHA auprès de Google
        data = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }

        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        r = requests.post(verify_url, data=data)
        result = r.json()

        if result.get('success'):
            # Débloquer ce client (par exemple supprimer ses clés Redis)
            client = Client.objects.filter(identifier=client_id).first()
            if client:
                key_base = client.ip_address or client.domain
                for window in [1, 10, 60, 3600]:
                    redis_client.delete(f"traffic:{key_base}:{window}")
            return Response({"status": "ok", "message": "Vérification réussie. Accès rétabli."})
        else:
            return Response({"status": "fail", "message": "Échec de validation reCAPTCHA."}, status=403)
