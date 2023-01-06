from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from user_app.models import User
from hr_api.user_profile.user_profile_serializers import UserProfileSerializer
from rest_framework.permissions import IsAuthenticated


class UserProfileAPI(APIView):
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        serializer = self.serializer_class(request.user)
        return Response({
            'status-code':200,
            'data':serializer.data,
            'msg':'get data'
        })

