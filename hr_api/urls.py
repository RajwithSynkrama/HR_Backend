from django.urls import path
from hr_api.user_authentication.user_authentication_api import (
    UserRegistrationAPI,
    UserLoginAPI,
    UserChangePasswordAPI,
    SendPasswordResetEmailAPI,
    UserPasswordResetAPI,
    )
from hr_api.user_profile.user_profile_api import *
urlpatterns = [
    path('api/registration/',UserRegistrationAPI.as_view(),name='registration'),
    path('api/login/',UserLoginAPI.as_view(),name='user-login'),
    path('api/user-profile/',UserProfileAPI.as_view(),name='profile'),
    path('api/changepassword/',UserChangePasswordAPI.as_view()),
    path('api/send-reset-password-email/',SendPasswordResetEmailAPI.as_view()),
    path('api/reset-password/<uid>/<token>/',UserPasswordResetAPI.as_view()),
]
