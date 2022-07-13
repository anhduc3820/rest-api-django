from marshmallow import schema, fields, validates_schema, validate
from rest_framework.exceptions import ValidationError
from apps.core import consts
from apps.core.schema import Meta


class CreateUserReq(schema.Schema):
    full_name = fields.Str(required=True)
    email = fields.Str(required=True)
    phone_number = fields.Str(required=True)
    user_password = fields.Str(required=True, validate=validate.Length(min=6))


class UserResp(schema.Schema):
    full_name = fields.Str()
    email = fields.Str()
    phone_number = fields.Str()


class CreateUserResponse(schema.Schema):
    meta = fields.Nested(Meta)
    data = fields.Nested(UserResp)


class LoginRequest(schema.Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True)


class LoginData(schema.Schema):
    access_token = fields.Str()
    full_name = fields.Str()
    email = fields.Str()
    phone_number = fields.Str()


class LoginResponse(schema.Schema):
    meta = fields.Nested(Meta)
    data = fields.Nested(LoginData)


class User(schema.Schema):
    full_name = fields.Str()
    email = fields.Str()
    phone_number = fields.Str()
    create_at = fields.Str()
    active = fields.Boolean()


class UserDetailResponse(schema.Schema):
    meta = fields.Nested(Meta)
    data = fields.Nested(User)
