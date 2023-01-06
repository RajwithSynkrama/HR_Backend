from django.db import models
from user_app.models import User
from utils.constants.constant import *
# Create your models here.
class OnboardingDocument(models.Model):
    """
       onboarding_id : PK
       user_id :       FK
       document :      FileField
       created_on :    DateTimeField
       last_modified : DateTimeField
       modified_by :   CharField


    """
    onboarding_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(User,related_name=ONBOARDING_DOCUMENT_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    document_upload = models.FileField(upload_to=ONBOARDING_DOCUMENT_URL_PATH)
    document_name = models.CharField(max_length=30)
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f" Onboarding Document : {self.document_name}"

class MiscDocument(models.Model):
    misc_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(User,related_name=MISC_DOCUMENT_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    document_name = models.CharField(max_length=20)
    document_path = models.URLField()
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Misc Document : {self.document_name}"
    



    
