from django.db import models
from user_app.models import User
from utils.constants.constant import *
# Create your models here.

class BankingInformation(models.Model):
    bank_info_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(User,related_name=BANKING_INFORMATION_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    bank_name = models.CharField(max_length=30)
    account_name = models.CharField(max_length=30)
    account_number = models.IntegerField(blank=False,null=False)
    ifsc_code = models.CharField(max_length=15)
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.account_name} -> {self.account_number}"
    