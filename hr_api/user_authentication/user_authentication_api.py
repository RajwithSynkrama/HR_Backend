from user_app.models import User
from utils.success_error_messages.registration_msg import RegistrationMessages,UserLoginMessages
from hr_api.user_authentication.user_authentication_serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserChangePasswordSerializer,
    SendPasswordResetEmailSerializer,
    UserPasswordResetSerializer,
    )

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from hr_api.user_authentication.renderers import UserRender
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from utils.success_error_messages.reset_password_msg import (
    UserChangePasswordMessages,
    UserPasswordResetMessages,
    )


# Get Current user token
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationAPI(APIView):
    """
        user registration api :-
        This API can be used to register :- 
        1) username,
        2) first_name,
        3) last_name,
        4) email,
        5) phone
        6) role
        7) password
        8) password2
    
    : parameter:
            parameters
            {
                "username":"CharField" **Required
            {

                "first_name": "CharField" 
            }
            {
                "last_name": "CharField"
            }
            {
                "email": "EmailField" **Required
            }
            {
                "phone": "CharField" **Required"
            }

            {
                "roll": "CharField" **Required"
            }
            {
                "password": "password" **Required
            }
            {
                "password2": "password" **Required
            }

            Sample parameters
            {
                "username":"rajraut",
                "first_name":"raj",
                "last_name":"raut",
                "email":"raj@gmail.com",
                "phone":"7712058875",
                "role":"employee",
                "password":"123",
                "password2":"123"
            }
            Response:-
            {
                "status-code": 201,
                "errors": false,
                "data": {
                    "username": "raj",
                    "first_name": "py",
                    "last_name": "pyth",
                    "email": "rautraj913@gmail.com",
                    "phone": "7712058875",
                    "role": "employee"
                },
                "message": "registration successfully",
                "Token": {
                    "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTY3MzA3MTQyMiwiaWF0IjoxNjcyOTg1MDIyLCJqdGkiOiIxNzAwY2M3Nzk2ODk0NmNhYmVjODYxYTExMmEyMTc2MCIsInVzZXJfaWQiOjE1fQ.-vY1J7MmQbL70Ef7wEQDYeQ6dBy5rNXlrLRHfe1dOyQ",
                    "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNjcyOTg4NjIyLCJpYXQiOjE2NzI5ODUwMjIsImp0aSI6ImQyYmUxYWM4MWNmOTRhZmQ5NjBiMGVjZWU4YjU3MDU5IiwidXNlcl9pZCI6MTV9.tiltT_qMXlWspOiZCDuXmsskHaTppBMy_27AoxS9a8Y"
                }
            }
            * Note *
            Authentication token is required.
    """
    renderer_classes = [UserRender]
    serializer_class = UserRegistrationSerializer
    def post(self,request,format=None):
        data = request.data
        serializer = self.serializer_class(data=data)
        if serializer.is_valid():
            user =serializer.save()
            token =get_tokens_for_user(user)
            serializer_data = serializer.data
            return Response(
                {
                'status-code':RegistrationMessages.SUCCESS_201,
                'errors':False,
                'data':serializer_data,
                'message':RegistrationMessages.SUCCESS_REGISTRATION,
                'Token':token
            })

        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
     

class UserLoginAPI(APIView):
    """
        user login API:-
        This API can be used to login:-
            1) username
            2) password
        :parameter
            parameters
            {
                "username":"CharField" **Required
            }
            {
                "password": "password" **Required
            }

        Sample parameters
        {
            "username":"raj",
            "password":"123"
        }

        Response:
        {
            "status-code": 200,
            "error": false,
            "message": "login successful",

            "Token": "{'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTY3MzA3MTQ0MSwiaWF0IjoxNjcyOTg1MDQxLCJqdGkiOiJlNjI0N2RmZDUxOGU0Mjg0OWI1MjNkYjA0NjBhZTY2ZiIsInVzZXJfaWQiOjE1fQ.XIwXle5A5MlLnhrOXchGOoVoI9oeRfrbeBBGeGW1WwI', 
                      'access': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNjcyOTg4NjQxLCJpYXQiOjE2NzI5ODUwNDEsImp0aSI6IjJlN2JjMTU5NzdjODRjMWI5YTY3ZTQ2ZWY0NWE0YTc2IiwidXNlcl9pZCI6MTV9.jePngE0JuXq-yUT20F1nPDBHpsaeIRVA1mic_Tglw0Q'
                      }"
        }
        * Note *
            Authentication token is  required.
    
    
    """
    # renderer_classes = [UserRender]
    serializer_class = UserLoginSerializer
    def post(self,request,format=None):
        data = request.data
        serializer =self.serializer_class(data=data)
       
        if serializer.is_valid(raise_exception=True):
            username = serializer.data.get('username')
            password = serializer.data.get('password')
            user = authenticate(username=username,password=password)
            if user is not None:
                token =get_tokens_for_user(user)
                return Response(
                    {
                    'status-code':RegistrationMessages.SUCCESS_200,
                    'error':False,
                    'message':UserLoginMessages.SUCCESS_LOGIN,
                    'Token':str(token)
                })
            else:
                return Response({'errors':{'non_field_errors':[UserLoginMessages.ERROR_USERNAME_OR_PASSWORD_NOT_VALID]}})
      

class UserChangePasswordAPI(APIView):
    """
     user Change password API:-
     This API can be used to change password:-
            1) password
            2) password2
    
    :parameter:
            parameters
            {
                "password": "password" **Required
            }
            {
                "password2": "password" **Required
            }

    Sample parameters
    {
        "password":"1234",
        "password2":"1234"
    }

    Response:
    {
        "message": "Password Changed Successfully"
    }
    * Note *
            Authentication token is  required.
    
    """
    permission_classes = [IsAuthenticated]

    serializer_class = UserChangePasswordSerializer
    def post(self,request,format=None):
        data = request.data
        serializer = self.serializer_class(data=data,context={'user':request.user})

        if serializer.is_valid(raise_exception=True):
            return Response({'message':UserChangePasswordMessages.SUCCESS_USER_CHANGE_PASSWORD})

        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailAPI(APIView):
    """
        This API can be used to send password reset email:-
            1) email
            
        :parameter:
                parameters
                {
                    "email": "EmailField" **Required
                }
        
        Sample parameters
        {
            "email":"rautraj913@gmail.com"
        }

        ample response
         {
            "message": "Password Reset link send .Please check your Email"
        }

        * Note *
            Authentication token is not required.

    """
    serializer_class = SendPasswordResetEmailSerializer
    def post(self,request,format=None):
        data =request.data
        serializer =self.serializer_class(data=data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message':UserChangePasswordMessages.SUCCESS_SEND_PASSWORD_EMAIL})
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetAPI(APIView):
    """
        user password rest API:-
        This API can be used to password reset:-
            1) password
            2) password2

        :parameter:   
            parameters  
            {
                "password": "password" **Required
            }
            {
                "password2": "password" **Required
            }  
        
        Sample parameters
        {
            "password":"1234",
            "password2":"1234"
        }

        Response:
        {
            "message": "Password Reset Successfully"
        }

    """
    serializer_class = UserPasswordResetSerializer
    # pass uid and token
    def post(self,request,uid,token,format=None):
        data = request.data
        serializer = self.serializer_class(data=data,context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message':UserPasswordResetMessages.SUCCESS_USER_PASSWORD_RESET_SUCCESSFULLY})
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
            

               

