from rest_framework import serializers
from user_app.models import User
from utils.constants.model_constants.user_app_constants import *

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model =User
        fields = [
            USER_FIELD_USER_ID,
            USER_FIELD_USERNAME,
            USER_FIELD_FIRST_NAME,
            USER_FIELD_LAST_NAME,
            USER_FIELD_EMAIL,
            USER_FIELD_PHONE,
            USER_FIELD_ROLE,

        ]