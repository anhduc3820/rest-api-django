from enum import Enum

DEFAULT_API_UID = 1
TOKEN_LENGTH = 32

CACHED_KEY_USER = "sg:user:{user_name}"


class DeviceType(Enum):
    MOBILE = "Mobile"
    FRONT_WEB = "FrontWeb"


class UserRole(Enum):
    USER = 1
    RESTAURANT_OWNER = 2
    CASHIER = 3
    MODERATOR = 4
    ADMIN = 5


class OrderStatus(Enum):
    PROGRESS = 0
    CONFIRMED = 1
    CANCEL = 2
