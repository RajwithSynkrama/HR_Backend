from django.db import models
from utils.constants.constant import *

# Create your models here.


class LeaveRequests(models.Model):
    """
       leave_id :  PK 
       user_id :   FK
       start_date : DateField
       end_date :   DateField
       leave_reason : CharField
       approved :     BooleanField
       decided_by : CharField
       decision_comment : CharField
       modified_by :   CharField
       created_on :  DateTimeField
       last_modified : DateTimeField
    """
    leave_request_id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey("user_app.User",related_name=LEAVE_REQUESTS_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    start_date = models.DateField()
    end_date = models.DateField()
    leave_reason = models.CharField(max_length=20,null=True,blank=True)
    approved = models.BooleanField(default=False)
    decided_by = models.CharField(max_length=20)
    decision_comment = models.CharField(max_length=20,null=True,blank=True)
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.leave_reason} Approved : {self.approved}"

class LeaveManagement(models.Model):
    leave_id = models.BigAutoField(primary_key=True)
    date = models.DateField()
    user_id = models.ForeignKey("user_app.User",related_name=LEAVE_MANAGEMENT_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    status = models.BooleanField(default=False)


    
