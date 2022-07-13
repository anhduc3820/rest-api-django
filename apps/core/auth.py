import logging
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication
from apps.users.models import User
from django.core.cache import cache

_logger = logging.getLogger(__name__)


class BearerAuthentication(TokenAuthentication):
    keyword = "Bearer"

    def authenticate_credentials(self, key):
        try:
            access_token = cache.get(key)
            if not access_token:
                msg = f"Authentication Failed: Access token not found {key}"
                raise exceptions.AuthenticationFailed(msg)

            email = access_token["email"]
            user = User.objects.get(email=email)

        except exceptions.AuthenticationFailed as err:
            _logger.info(err)
            raise exceptions.AuthenticationFailed("Invalid token")
        except Exception as e:
            _logger.exception(e)
            raise exceptions.AuthenticationFailed("Invalid token")

        return (user, key)
