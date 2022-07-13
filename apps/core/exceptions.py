from rest_framework import status
from rest_framework.exceptions import (
    ValidationError,
    NotFound,
    APIException,
    AuthenticationFailed,
)


class HTTP400BadRequestError(ValidationError):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Bad request"
    default_code = "Bad request"


class HTTP401Unauthorized(AuthenticationFailed):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Unauthorized user"
    default_code = "Unauthorized"


class HTTP404NotFoundError(NotFound):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "Not found resource"
    default_code = "Not found"


class HTTP409ConflictError(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Conflict resource"
    default_code = "conflict"


class HTTP403Forbidden(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "You do not have permission to perform this action."
    default_code = "permission_denied"
