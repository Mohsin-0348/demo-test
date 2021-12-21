# at w3universal/backend/users/choices.py
"""All choices for users"""
from django.db import models


class RoleChoices(models.TextChoices):
    ADMIN = 'admin'
    MEMBER = 'member'
    EMPLOYEE = 'employee'


class GenderChoices(models.TextChoices):
    Female = "female"
    Male = "male"
    Others = "others"


class SocialAccountTypeChoices(models.TextChoices):
    FACEBOOK = 'facebook'
    GOOGLE = 'google'
    APPLE = 'apple'


class DeviceTypeChoices(models.TextChoices):
    IOS = "ios"
    ANDROID = "android"
    WEB = "web"
