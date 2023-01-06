from django.contrib import admin
from django.contrib.auth.models import Group
from user_app.models import User,UserProfile,SocialProfile,EmployeeSalary,WorkingHours,PublicHoliday
# Register your models here.
admin.site.register(User)
admin.site.register(UserProfile)
admin.site.register(SocialProfile)
admin.site.register(EmployeeSalary)
admin.site.register(WorkingHours)
admin.site.register(PublicHoliday)
admin.site.unregister(Group)