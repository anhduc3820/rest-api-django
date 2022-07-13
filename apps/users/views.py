import logging

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework import status, generics
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from apps.core import consts, api_status_code, paginations
from apps.core.responses import ResponseObject
from apps.users import schema, utils
from apps.core.schema import validate_data, serialize_data
from rest_framework.response import Response
from apps.core.auth import BearerAuthentication
from apps.core import utils as core_utils
from django.core.cache import cache

_logger = logging.getLogger(__name__)


# Create your views here.

class CreateUser(APIView):
    permission_classes = (AllowAny,)

    @transaction.atomic()
    def post(self, request):
        _resp = ResponseObject()

        valid_data = validate_data(schema.CreateUserReq, request.data)
        email = valid_data.get("email")

        if utils.get_user_by_email(email):
            _logger.info(f"email exits with email: {email}")
            _resp.meta = {
                "code": api_status_code.EMAIL_EXIST,
                "message": f"Email exist !!!"
            }
            data = serialize_data(schema.CreateUserResponse, _resp)
            return Response(data, status=status.HTTP_409_CONFLICT)

        user = utils.create_user(
            full_name=valid_data.get("full_name"),
            phone_number=valid_data.get("phone_number"),
            password=valid_data.get("user_password"),
            email=email
        )

        _resp.data = user
        data = serialize_data(schema.CreateUserResponse, _resp)
        return Response(data, status=status.HTTP_200_OK)


class LoginUserAPI(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        _resp = ResponseObject()
        valid_data = validate_data(schema.LoginRequest, request.data)
        email = valid_data.get("email")
        password = valid_data.get("password")

        user = utils.get_user_by_email(email)
        if not user:
            _logger.info(f"user not exits with email: {email}")
            _resp.meta = {
                "code": api_status_code.NOT_FOUND,
                "message": f"user not exist !!!"
            }
            data = serialize_data(schema.LoginResponse, _resp)
            return Response(data, status=status.HTTP_404_NOT_FOUND)

        is_pass = utils.verify_hash_password(password=password, hash_password=user.password)
        if not is_pass:
            _logger.info(f"Incorrect password with email: {email}")
            _resp.meta = {
                "code": api_status_code.INCORRECT_PASSWORD,
                "message": f"Incorrect password !!!"
            }
            data = serialize_data(schema.LoginResponse, _resp)
            return Response(data, status=status.HTTP_403_FORBIDDEN)

        now = timezone.now()
        ip_address = core_utils.get_ip_address(request)
        _logger.info(
            f"IP_ADDR {ip_address} "
            f"USER email: {user.email}, full_name: {user.full_name} logged in!"
        )

        # Gen and save access token into Redis
        access_token = utils.generate_access_key()
        expire_time = utils.get_expired_time_access_token(now)
        acc_token_info = {
            "user": user.full_name,
            "email": user.email,
        }
        utils.handle_user_login_same_device_type(
            user.id, acc_token_info, expire_time, access_token
        )

        user.access_token = access_token
        _resp.data = user
        data = serialize_data(schema.LoginResponse, _resp)
        return Response(data, status=status.HTTP_200_OK)


class GetUserDetail(APIView):
    authentication_classes = [BearerAuthentication]

    def get(self, request):
        _resp = ResponseObject()
        user = request.user

        _resp.data = user
        data = serialize_data(schema.UserDetailResponse, _resp)
        return Response(data, status=status.HTTP_200_OK)
