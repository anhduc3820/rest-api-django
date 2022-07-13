from django.db import models


class CommonInfo(models.Model):
    """Abstract model contains common Odoo columns"""

    create_at = models.DateTimeField(auto_now_add=True)
    active = models.BooleanField(default=True)

    class Meta:
        abstract = True
