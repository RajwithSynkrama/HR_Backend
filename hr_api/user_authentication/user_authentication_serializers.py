from rest_framework import serializers
from user_app.models import User
from django.core.exceptions import ValidationError
from utils.constants.model_constants.user_app_constants import *
from utils.success_error_messages.registration_msg import *
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from hr_api.user_authentication.utils import Utils

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True,write_only=True)
    password2 = serializers.CharField(required=True,write_only=True)
    class Meta:
        model =User
        fields = [
            USER_FIELD_USERNAME,
            USER_FIELD_FIRST_NAME,
            USER_FIELD_LAST_NAME,
            USER_FIELD_EMAIL,
            USER_FIELD_PASSWORD,
            USER_FIELD_PASSWORD2,
            USER_FIELD_PHONE,
            USER_FIELD_ROLE
            
        ]
        extra_kwargs={
            'password':{'write_only':True},
            'password2':{'write_only':True}
        }

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"Password":ERROR_BOTH_PASSWORD_DO_NOT_MATCH})
        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError({'error':ERROR_EMAIL_IS_ALREADY_IS_USE})
        return super().validate(data)

    def create(self, validated_data):
      
        user =  User.objects.create(
        username = validated_data['username'],
        email = validated_data['email'],
        first_name  = validated_data['first_name'],
        last_name  = validated_data['last_name'],
        role =validated_data['role'],
        phone = validated_data['phone'],
        password = validated_data['password'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user 

class UserLoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length= 25)
    class Meta:
        model = User
        fields = [USER_FIELD_USERNAME,USER_FIELD_PASSWORD]


class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        fields = [USER_FIELD_PASSWORD,USER_FIELD_PASSWORD2]

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user =self.context.get('user')
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password":ERROR_BOTH_PASSWORD_DO_NOT_MATCH})
        user.set_password(password)
        user.save()
        return super().validate(attrs)

class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    email =serializers.EmailField(max_length=255)
    class Meta:
        model =User
        fields=[USER_FIELD_EMAIL]

    def validate(self, attrs):
        email=attrs.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            # get user id 
            uid = urlsafe_base64_encode(force_bytes(user.user_id))
            print("Encoded UID --->",uid)
            # generate Token User for rest password
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Rest Token -->',token)
            # generate link reset Password
            link = 'http//localhost:3000/api/user/reset/'+uid+'/'+token
            print("Password Reset Link -->",link)
            # Send Email
            body= 'Click Following Link to Reset Your Password'+link
            data ={
                'subject':'Reset your Password',
                'body':body,
                'to_email':user.email
            }
            Utils.send_email(data)
            return attrs
        else:
            raise ValidationError('Yor are not a Registered User') 


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        fields = [USER_FIELD_PASSWORD,USER_FIELD_PASSWORD2]

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token =self.context.get('token')
            if attrs['password'] != attrs['password2']:
                raise serializers.ValidationError({"password":ERROR_BOTH_PASSWORD_DO_NOT_MATCH})
            # convert id in string
            user_id = smart_str(urlsafe_base64_decode(uid))
            #get user
            user = User.objects.get(user_id=user_id)
            # check token validate or not 
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise ValidationError("Token is not Valid or Expired ")
            user.set_password(password)
            user.save()
            return super().validate(attrs)
        except DjangoUnicodeDecodeError:
            PasswordResetTokenGenerator().check_token(user,token)
            raise ValidationError("Token is not Valid or Expired ")

       
        
      
       