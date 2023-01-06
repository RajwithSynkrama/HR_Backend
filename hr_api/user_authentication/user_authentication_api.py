
from user_app.models import User
from utils.success_error_messages.registration_msg import RegistrationMessages,UserLoginMessages
from hr_api.user_authentication.user_authentication_serializers import UserRegistrationSerializer,UserLoginSerializer,UserChangePasswordSerializer,SendPasswordResetEmailSerializer,UserPasswordResetSerializer
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from hr_api.user_authentication.renderers import UserRender
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Token Jwt
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegistrationAPI(APIView):
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
    permission_classes = [IsAuthenticated]

    serializer_class = UserChangePasswordSerializer
    def post(self,request,format=None):
        data = request.data
        serializer = self.serializer_class(data=data,context={'user':request.user})

        if serializer.is_valid(raise_exception=True):
            return Response({'message':'Password Changed Successfully'})

        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailAPI(APIView):
    serializer_class = SendPasswordResetEmailSerializer
    def post(self,request,format=None):
        data =request.data
        serializer =self.serializer_class(data=data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message':'Password Reset link send .Please check your Email'})
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetAPI(APIView):
    serializer_class = UserPasswordResetSerializer
    # pass uid and token
    def post(self,request,uid,token,format=None):
        data = request.data
        serializer = self.serializer_class(data=data,context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'message':'Password Reset Successfully'})
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
            

               

