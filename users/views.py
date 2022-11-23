from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import get_object_or_404
from users.models import User
from rest_framework.permissions import IsAuthenticated
from users.serializers import UserSerializer, ProfileEditSerializer
import json, bcrypt, jwt
from django.core.exceptions import ValidationError
from OIL_PAINTING_BE.settings import SECRET_KEY, ALGORITHM


class UserView(APIView):
    def post(self, request) :
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid() :
            hashed_password = bcrypt.hashpw(request.data["password"].encode("utf-8"), bcrypt.gensalt())
            serializer.save(password = hashed_password.decode("utf-8"))
            return Response({"message":"가입완료!"}, status=status.HTTP_201_CREATED)
        else : 
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
    def delete(self, request):
        user = get_object_or_404(User, id=request.user.id)
        if user:
            user.delete()
            return Response({"message":"지금까지 저희 서비스를 이용해 주셔서 감사합니다."}, status=status.HTTP_200_OK)
        return Response({"message":"이런... 탈퇴에 실패하셨습니다."}, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView) :
    def post(self, request) :
        try_email = request.data["email"]
        try_password = request.data["password"]
        user = get_object_or_404(User, email = try_email)
        
        if not user :
            raise ValidationError({"INVALID_EMAIL" : "존재하지 않는 이메일입니다."})
        
        validating_password = bcrypt.checkpw(try_password.encode("utf-8"), user.password.encode("utf-8"))
        
        if not validating_password :
            raise ValidationError({"password" : "틀린 비밀번호입니다."})
        
        access_token = jwt.encode({"id": user.id}, SECRET_KEY, algorithm=ALGORITHM)
        
        def decoding_access_token(access_token, SECRET_KEY) :
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=ALGORITHM)
            return payload
        
        user_info = decoding_access_token(access_token, SECRET_KEY)
        
        return Response({"message":f"환영합니다, {user_info}님!", "access_token" : access_token}, status=status.HTTP_200_OK)
        


class ProfileView(APIView) :
    permission_classes = [IsAuthenticated]
        
    # 닉네임과 비밀번호 변경
    def put(self, request) :
        user = get_object_or_404(User, id=request.user.id)
        if user == request.user :
            serializer = ProfileEditSerializer(user, data=request.data, context={"request":request})
            if serializer.is_valid() :
                serializer.save()
                return Response({"message":"변경 완료!"}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response({"message":"본인만 수정할 수 있습니다"}, stauts=status.HTTP_403_FORBIDDEN)