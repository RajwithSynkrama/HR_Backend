from django.contrib import admin
from leave_app.models import LeaveManagement,LeaveRequests
# Register your models here.
admin.site.register(LeaveManagement)
admin.site.register(LeaveRequests)