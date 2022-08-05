from statistics import mode
from unittest.util import _MAX_LENGTH
from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
#class CustomUser(AbstractUser):
    # username = models.CharField(max_length=10)
    #university = models.CharField(max_length=100)
    #track = models.CharField(max_length=10)
    # USERNAME_FIELD = 'username'
    
class Accounts(models.Model):
    user_id = models.CharField(max_length=128, unique=True, null=True)
    kakao_nickname = models.CharField(max_length=128)
    university = models.CharField(max_length=128,null=True)
    track = models.CharField(max_length=128, null= True)
    username = models.CharField(max_length=10,null=True)
    smallTalk = models.CharField(max_length=128, null=True)
    token=models.CharField(max_length=128, null=True)
