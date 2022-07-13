import binascii
import logging
import os
from django.http import HttpRequest
from rest_framework.exceptions import NotAuthenticated, ValidationError
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.response import Response
from rest_framework import status, exceptions
from apps.core import consts
from apps.core.exceptions import (
    HTTP404NotFoundError,
    HTTP403Forbidden,
    HTTP409ConflictError,
    AuthenticationFailed,
)
from apps.core.responses import ResponseObject
from apps.core.schema import serialize_data, MetaErr
from django.core.cache import cache

_logger = logging.getLogger(__name__)


def generate_key():
    num_bytes = consts.TOKEN_LENGTH
    token = binascii.hexlify(os.urandom(num_bytes)).decode()
    return str(token)


def exception_handler(exc, context):
    if isinstance(
        exc,
        (
            NotAuthenticated,
            HTTP404NotFoundError,
            ValidationError,
            HTTP409ConflictError,
            HTTP403Forbidden,
            AuthenticationFailed,
            exceptions.MethodNotAllowed,
        ),
    ):
        _logger.info(f'{context.get("view")}:{type(exc)} {exc}')
    else:
        _logger.exception(exc)
    response = drf_exception_handler(exc, context)
    if response is None:
        _resp = ResponseObject()
        _resp.meta = {
            "code": 500,
            "message": "Something went wrong, please try again later!",
        }
        data = serialize_data(MetaErr, _resp)
        return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return response


def get_ip_address(request: HttpRequest) -> str:
    """Return client's real IP address

    When API is deployed behind proxy server (e.g: Nginx)
    return value of HTTP_X_FORWARDED_FOR header.
    Otherwise, return value of REMOTE_ADDR header
    """
    ip_base = request.META.get("HTTP_X_FORWARDED_FOR")
    ip_remote_addr = request.META.get("REMOTE_ADDR")
    ip_address = ip_base if ip_base else ip_remote_addr
    return ip_address


def get_access_token(request: HttpRequest) -> str:
    """Return client's Access Token

    Parse and return access token as str from Authorization header.
    Return None if not found, or parse error
    """
    try:
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        access_token = auth_header.split()[1]
        return access_token
    except:  # noqa
        return None


def req_str(request: HttpRequest) -> str:
    """Convert Django's request to str for logging"""
    return f"{request.method} {request.get_full_path()}"


class LoggingMiddleware:
    """
    Middleware handle logging when a request is made
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        self.before_view_handle(request)

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.
        self.after_view_handle(request, response)
        return response

    def before_view_handle(self, request: HttpRequest):
        """
        Called when request is made
        """
        ip_address = get_ip_address(request)
        req = req_str(request)
        try:
            key = get_access_token(request)
            no_user_msg = (
                f"Receive request, ip: {ip_address}, user_id: NULL, "
                f"email: NULL, trading_id: NULL, api: {req}"
            )
            if not key:
                _logger.info(no_user_msg)
                return

            acc_token_info = cache.get(key)
            if not acc_token_info:
                _logger.info(no_user_msg)
                return

            user_id = acc_token_info.get("user")
            email = acc_token_info.get("login_email")
            trading_id = acc_token_info.get("trading_id")
            _logger.info(
                f"Receive request, ip: {ip_address}, user_id: {user_id}, "
                f"email: {email}, trading_id: {trading_id}, api: {req}"
            )

        except Exception as err:
            _logger.info(no_user_msg)
            _logger.exception(err)

    def after_view_handle(self, request: HttpRequest, response: Response):
        """
        Called when a view is start processing
        """
        ip_address = get_ip_address(request)
        req = req_str(request)
        no_user_msg = (
            f"Finish request, ip: {ip_address}, user_id: NULL, "
            f"email: NULL, trading_id: NULL, api: {req}"
        )
        try:
            key = get_access_token(request)
            if not key:
                _logger.info(no_user_msg)
                return

            acc_token_info = cache.get(key)
            if not acc_token_info:
                _logger.info(no_user_msg)
                return

            user = acc_token_info.get("user")
            user_name = acc_token_info.get("user_name")
            email = acc_token_info.get("email")
            _logger.info(
                f"Finish request, ip: {ip_address}, user: {user_name}, "
                f"email: {email}, api: {req}"
            )

        except Exception as err:
            _logger.info(no_user_msg)
            _logger.exception(err)
