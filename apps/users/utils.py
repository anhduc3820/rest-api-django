import datetime
import os
import logging
import binascii
from apps.users import models
import django.utils.timezone as timezone
from passlib.hash import pbkdf2_sha512
from apps.core import consts
from django.conf import settings
from datetime import timedelta
from django.core.cache import cache


_logger = logging.getLogger(__name__)


def create_user(
    full_name: str,
    phone_number: str,
    password: str,
    email: str
) -> models.User:
    user = models.User(
        full_name=full_name,
        phone_number=phone_number,
        password=make_odoo_password(password),
        email=email,
        create_at=timezone.now(),
        active=True
    )
    user.save()
    return user


def get_user_by_email(email: str) -> models.User:
    return models.User.objects.filter(email=email).first()


def make_odoo_password(password: str) -> str:
    """Create an encoded Odoo database value for password
    The result is Odoo normally formatted as "$algorithm$salt$hash"
    """
    return pbkdf2_sha512.hash(password)


def verify_hash_password(password: str, hash_password: str) -> bool:
    """Check if the given password is correct."""
    return pbkdf2_sha512.verify(password, hash_password)


def generate_access_key():
    num_bytes = consts.TOKEN_LENGTH
    token = binascii.hexlify(os.urandom(num_bytes)).decode()
    return str(token)


def get_expired_time_access_token(create_time: datetime.datetime):
    return (
        create_time + timedelta(seconds=settings.ACCESS_TOKEN_TIMEOUT),
        settings.ACCESS_TOKEN_TIMEOUT
    )


def handle_user_login_same_device_type(
    user_name: int, acc_token_info: dict, expire_time, access_token
):
    is_user_logged_in = check_user_exist_cache(str(user_name))
    device_key = consts.CACHED_KEY_USER.format(user_name=user_name)
    if is_user_logged_in:
        token_binary = cache.get(device_key).get(b"token_key")
        old_access_token = token_binary.decode() if token_binary else None
        token_key = cache.get(old_access_token) if old_access_token else None
        if not old_access_token or not token_key:
            cache.set(access_token, acc_token_info, expire_time[1])
            save_user_cache(user_name, access_token)
            return

        _logger.info(f"Delete old access token: {old_access_token}")
        cache.delete_many(old_access_token, device_key)
    cache.set(access_token, acc_token_info, expire_time[1])
    save_user_cache(user_name, access_token)


def check_user_exist_cache(user_name: str) -> bool:
    hash_key = consts.CACHED_KEY_USER.format(user_name=user_name)

    data = cache.get(hash_key)
    if data:
        return data.get("user") == user_name.encode()
    return False


def save_user_cache(user_name: int, token_key: str):
    hash_key = consts.CACHED_KEY_USER.format(user_name=user_name)
    data = {"user_name": user_name, "token_key": token_key}
    cache.set(hash_key, data)
