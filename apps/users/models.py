from django.db import models
from apps.core.models import CommonInfo


# Create your models here.

class User(CommonInfo):
    full_name = models.CharField(max_length=1024)
    email = models.CharField(unique=True, max_length=2147483647)
    phone_number = models.CharField(max_length=12)
    password = models.CharField(max_length=1024)

    class Meta:
        db_table = "users"
