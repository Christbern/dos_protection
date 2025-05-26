from django.db import models

class Client(models.Model):
    identifier = models.CharField(max_length=255, unique=True)  # ex : ID client transmis dans la requête
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    domain = models.CharField(max_length=255, null=True, blank=True)
    # Autres attributs possibles selon l'architecture du système:
    # sous-domaine, addresse ip partagé si c'est le cas, etc.
    def __str__(self):
        return self.identifier
