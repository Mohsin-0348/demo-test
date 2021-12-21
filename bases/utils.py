import os
import random
import re
import string
import uuid

from django.conf import settings
from django.utils.text import slugify
from graphql import GraphQLError


def generate_auth_key():
    key = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
    key = 'w3AC' + key
    return key


def create_token():
    return uuid.uuid4()


def build_absolute_uri(path) -> str:
    return f"http://{settings.SITE_URL}/{path}"


def get_json_data(request) -> object:
    data = {i[0]: i[1] for i in request.META.items() if i[0].startswith('HTTP_')}
    return data


def email_checker(email):
    regex = r"^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$"
    if (re.search(regex, email)):
        return True
    return False


def username_validator(name):
    regex = r'^[\w][\w\d_]+$'
    if (re.search(regex, name)):
        return True
    return False


def divide_chunks(list_d, n):
    for i in range(0, len(list_d), n):
        yield list_d[i: i + n]


def get_tenant():
    domain = None
    return domain


# To get extension from upload file
def get_filename_exist(file_path):
    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)
    return name, ext


# To save Book image with new name by function
def user_image_path(instance, file_name):
    user_id = slugify(instance.id)
    new_filename = random.randint(1, 101119)
    name, ext = get_filename_exist(file_name)
    final_filename = f'{new_filename}{ext}'
    return f"user/{user_id}/profile/{final_filename}"


def raise_error(message, errors, code):
    raise GraphQLError(
        message=message,
        extensions={
            "errors": errors,
            "code": code
        }
    )


def get_object(model, object_id):
    try:
        obj = model.objects.get(id=object_id)
        return obj
    except model.DoesNotExist:
        raise GraphQLError(
            message="Matching query does not exist.",
            extensions={
                "errors": {"object_id": "No instance found associated with this object-id"},
                "code": "invalid_object_id"
            }
        )


def raise_does_not_exist(attr, object_type="instance"):
    raise GraphQLError(
        message="Matching query does not exist.",
        extensions={
            "errors": {attr: f"No {object_type} found associated with this {attr}"},
            "code": f"invalid_{attr}"
        }
    )
