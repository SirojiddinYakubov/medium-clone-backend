import random
from django.conf import settings
from rest_framework import status, permissions, generics, parsers
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate, update_session_auth_hash
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .utils import Email

from .enums import TokenType
from .serializers import (UserSerializer, LoginSerializer, ValidationErrorSerializer, TokenResponseSerializer,
    UserUpdateSerializer, ChangePasswordSerializer, )
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, extend_schema_view
from django_redis import get_redis_connection

from .services import TokenService, UserService

User = get_user_model()


@extend_schema_view(
    post=extend_schema(
        summary="Sign up a new user",
        request=UserSerializer,
        responses={
            201: UserSerializer,
            400: ValidationErrorSerializer
        }
    )
)
class SignupView(APIView):
    serializer_class = UserSerializer
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            user_data = UserSerializer(user).data
            return Response({
                'user': user_data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@extend_schema_view(
    post=extend_schema(
        summary="Log in a user",
        request=LoginSerializer,
        responses={
            200: TokenResponseSerializer,
            400: ValidationErrorSerializer,
        }
    )
)
class LoginView(APIView):
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            request,
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )

        if user is not None:
            tokens = UserService.create_tokens(user)
            return Response(tokens, status=status.HTTP_200_OK)
        else:
            return Response({'detail': 'Hisob maʼlumotlari yaroqsiz'}, status=status.HTTP_401_UNAUTHORIZED)


@extend_schema_view(
    get=extend_schema(
        summary="Get user information",
        responses={
            200: UserSerializer,
            400: ValidationErrorSerializer
        }
    ),
    patch=extend_schema(
        summary="Update user information",
        request=UserUpdateSerializer,
        responses={
            200: UserUpdateSerializer,
            400: ValidationErrorSerializer
        }
    )
)
class UsersMe(generics.RetrieveAPIView, generics.UpdateAPIView):
    http_method_names = ['get', 'patch']
    queryset = User.objects.filter(is_active=True)
    parser_classes = [parsers.MultiPartParser]
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user

    def get_serializer_class(self):

        user = self.request.user
        code = random.randint(10000, 99999)
        Email.send_email(user, code)

        if self.request.method == 'PATCH':
            return UserUpdateSerializer
        return UserSerializer

    def patch(self, request, *args, **kwargs):
        redis_conn = get_redis_connection('default')
        redis_conn.set('test_key', 'test_value', ex=3600)
        cached_value = redis_conn.get('test_key')
        print(cached_value)

        return super().partial_update(request, *args, **kwargs)


@extend_schema_view(
    post=extend_schema(
        summary="Log out a user",
        request=None,
        responses={
            200: ValidationErrorSerializer,
            401: ValidationErrorSerializer
        }
    )
)
class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses=None)
    def post(self, request, *args, **kwargs):
        TokenService.add_token_to_redis(
            request.user.id,
            'fake_token',
            TokenType.ACCESS,
            settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME"),
        )
        TokenService.add_token_to_redis(
            request.user.id,
            'fake_token',
            TokenType.REFRESH,
            settings.SIMPLE_JWT.get("REFRESH_TOKEN_LIFETIME"),
        )
        return Response({"detail": "Mufaqqiyatli chiqildi."}, status=status.HTTP_200_OK)


@extend_schema_view(
    put=extend_schema(
        summary="Change user password",
        request=ChangePasswordSerializer,
        responses={
            200: TokenResponseSerializer,
            401: ValidationErrorSerializer
        }
    )
)
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def put(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            request,
            username=request.user.username,
            password=serializer.validated_data['old_password']
        )

        if user is not None:
            user.set_password(serializer.validated_data['new_password'])
            user.save()

            update_session_auth_hash(request, user)

            tokens = UserService.create_tokens(user)

            TokenService.add_token_to_redis(
                request.user.id,
                tokens['access'],
                TokenType.ACCESS,
                settings.SIMPLE_JWT.get("ACCESS_TOKEN_LIFETIME"),
            )
            TokenService.add_token_to_redis(
                request.user.id,
                tokens['refresh'],
                TokenType.REFRESH,
                settings.SIMPLE_JWT.get("REFRESH_TOKEN_LIFETIME"),
            )

            return Response({
                "access": tokens['access'],
                "refresh": tokens['refresh'],
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                "detail": "Eski parol xato."
            }, status=status.HTTP_400_BAD_REQUEST)
