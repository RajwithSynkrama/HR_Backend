from django.db import models
from django.contrib.auth.models import AbstractUser
from utils.constants.model_constants.user_app_constants import USER_ROLL,DAY_TYPE
from utils.constants.constant import *
from leave_app.models import LeaveManagement
# Create your models here.

class User(AbstractUser):

    """
    # user_roll
        1.hr
        2.project manager
        3.super admin
        4.admin
        5.accounts
        6.sales
        7.marketing
        8.employee 

    user_id : PK
    role : Enum
    email  : CharField **required
    phone : EmailField
    email_otp       : CharField
    is_email_verified : BooleanField
    otp_expire: CharField
    created_on: DateTimeField
    last_modified: DateTimeField

    """
    user_id = models.BigAutoField(primary_key=True)
    role = models.CharField(max_length=16,choices=USER_ROLL)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=12,unique=True,null=True,blank=True)
    email_otp = models.CharField(max_length=6,null=True,blank=True)
    is_email_verified = models.BooleanField(default=False)
    email_otp_expired_at = models.DateTimeField(null=True,blank=True)
    created_on = models.DateField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.username}"

class UserProfile(models.Model):
    """
      ## COLUMN NAME              ## DATA TYPE

        profile_id :                PK
        user_id    :                FK
        date_of_birth :             DateField (not required)
        permanent_address_line_1 : TextField
        permanent_address_line_2 : TextField
        permanent_city :           CharField
        permanent_state :          CharField
        permanent_zipcode :        CharField
        permanent_country :        CharField
        current_address_line_1 :   TextField
        current_address_line_2 :   TextField
        current_city :             CharField
        current_state :            CharField
        current_zipcode :          CharField
        current_country :          CharField
        emergency_contact_number_1: CharField
        emergency_contact_number_2: CharField
        created_on :                DateTimeField
        last_modified :             DateTimeField
        modified_by   :             CharField

    """
    profile_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(User,related_name=USER_PROFILE_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    date_of_birth = models.DateField(null=True)
    permanent_address_line_1 = models.TextField()
    permanent_address_line_2 = models.TextField(null=True,blank=True)
    permanent_city = models.CharField(max_length=20)
    permanent_state = models.CharField(max_length=20)
    permanent_zipcode = models.CharField(max_length=6)
    current_address_line_1 = models.TextField()
    current_address_line_2 = models.TextField(null=True,blank=True)
    current_city = models.CharField(max_length=20)
    current_state = models.CharField(max_length=20)
    current_zipcode = models.CharField(max_length=6)
    current_country = models.CharField(max_length=20)
    emergency_contact_number_1 = models.CharField(max_length=12,null=True)
    emergency_contact_number_2 = models.CharField(max_length=12,null=True,blank=True)
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user_id.username}"

class SocialProfile(models.Model):
    """
        ## COLUMN NAME      ## Data Type

        social_profile_id : PK
        user_id :           FK
        social_media :      URLField   
        created_on :        DateTimeField
        last_modified :     DateTimeField
        modified_by :       CharField

    """
    social_profile_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(User,related_name=SOCIAL_PROFILE_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    social_media = models.URLField(max_length=20,null=True,blank=True)
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.social_media} --> ID {self.social_profile_id}"

class EmployeeSalary(models.Model):
    salary_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(User,related_name=EMPLOYEE_SALARY_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    revision_id = models.CharField(max_length=20,null=True,blank=True)
    designation = models.CharField(max_length=20)
    effective_from = models.DateField()
    revised_On = models.DateField()
    joining_bonus = models.IntegerField()
    basic = models.CharField(max_length=20)
    hra = models.CharField(max_length=20)
    performance = models.CharField(max_length=30,null=True,blank=True)
    itr = models.CharField(max_length=20)
    conveyance_allowance = models.CharField(max_length=20)
    medical_healthcare = models.CharField(max_length=20)
    deduction = models.CharField(max_length=20)
    ctc = models.CharField(max_length=50)
    in_hand = models.CharField(max_length=20)
    bonus = models.CharField(max_length=20)
    others = models.CharField(max_length=20,null=True,blank=True)
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.salary_id} User: {self.user_id.username}"


class WorkingHours(models.Model):
    """
        salary_id : PK
        user_id :   FK
        revision_id : CharField
        designation : CharField
        effective_from : DateField
        revised_On :  DateField
        joining_bonus : IntegerField
        basic :         CharField
        hra :           hra
        performance :   CharField  
        retention :     CharField
        itr :           CharField
        convenience_allowance : CharField
        medical_healthcare : CharField
        deduction :     CharField
        ctc :           CharField
        in_hand :       CharField
        bonus :        CharField
        others :        CharField
        created_on :    DateTimeField
        last_modified : DateTimeField
        modified_by : CharField

    """
    hours_id = models.BigAutoField(primary_key=True)
    user_id = models.ForeignKey(User,related_name=WORKING_HOURS_USER_ID_MODEL_MANAGER,on_delete=models.CASCADE)
    leave_id = models.ForeignKey(LeaveManagement,related_name=WORKING_HOURS_LEAVE_ID_MODEL_MANAGER,on_delete=models.CASCADE,null=True,blank=True)
    from_time = models.TimeField()
    to_time = models.TimeField()
    total_hours = models.CharField(max_length=20)
    day_type = models.CharField(max_length=10,choices=DAY_TYPE)
    modified_by = models.CharField(max_length=20,null=True,blank=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Total : {self.total_hours}"


class PublicHoliday(models.Model):
    holiday_id = models.BigAutoField(primary_key=True)
    date = models.DateField()
    reason = models.TextField()

    
   



    




























