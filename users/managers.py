# at w3universal/backend/users/managers.py
from django.conf import settings
from django.contrib.auth.models import BaseUserManager
from django.utils import timezone

from users.choices import RoleChoices


class UserManager(BaseUserManager):
    def create_base(
        self,
        username,
        email,
        password,
        is_staff,
        is_superuser,
        role,
        **extra_fields
    ) -> object:
        """
        Create User With Email name password
        """
        if not email:
            raise ValueError("User must have an email")
        user = self.model(
            username=username,
            email=email,
            is_staff=is_staff,
            is_superuser=is_superuser,
            role=role,
            **extra_fields
        )
        print(user.role)
        user.set_password(password)
        user.save(using=self.db)
        return user

    def create_user(
        self,
        username,
        email,
        password=None,
        role=RoleChoices.MEMBER,
        **extra_fields
    ) -> object:
        """Creates and save non-staff-normal user
        with given email, username and password."""

        return self.create_base(
            username,
            email,
            password,
            False,
            False,
            role,
            **extra_fields
        )

    def create_superuser(
        self,
        username,
        email,
        password,
        **extra_fields
    ) -> object:
        """Creates and saves super user
        with given email, name and password."""
        return self.create_base(
            username,
            email,
            password,
            True,
            True,
            RoleChoices.ADMIN,
            **extra_fields
        )


class UserPasswordResetManager(BaseUserManager):

    def check_key(self, token, email):
        if not token:
            return False

        try:
            row = self.get(
                token=token, user__email=email,
                created_on__gte=timezone.now() - timezone.timedelta(minutes=settings.PASSWORD_RESET_TIMESTAMP)
            )
            row.delete()
            return True
        except self.model.DoesNotExist:
            return False

    def create_or_update(self, user, token):
        try:
            row = self.get(user=user)
            row.token = token
            row.save()
            return row
        except self.model.DoesNotExist:
            return self.create(user=user, token=token)


class UserSocialAccountManager(BaseUserManager):

    def checkSocialAccount(self, social_id, social_type, email):
        if not social_id or not social_type:
            return False
        try:
            if social_type in ['apple', 'facebook']:
                row = self.filter(social_id=social_id, social_type=social_type).latest('updated_on')
            else:
                row = self.get(social_id=social_id, social_type=social_type, user__email=email)
            return row.user
        except self.model.DoesNotExist:
            return False

    def create_or_update(self, user, social_type, social_id):
        try:
            row = self.get(user=user, social_id=social_id)
            row.social_id = social_id
            row.save()
            return row
        except self.model.DoesNotExist:
            return self.create(user=user, social_type=social_type, social_id=social_id)


class UserDeviceTokenManager(BaseUserManager):

    def create_or_update(self, user, device_type, device_token):
        try:
            print(user, device_token, device_type)
            raw = self.get(user=user)
            raw.device_token = device_token
            raw.device_type = device_type
            raw.save()
            return raw
        except self.model.DoesNotExist:
            return self.create(
                user=user,
                device_type=device_type,
                device_token=device_token
            )


class UserOTPManager(BaseUserManager):
    """
        check user OTP if Exist
    """
    def check_otp(self, otp, user):
        if not otp:
            return False
        try:
            row = self.get(otp=otp, user=user)
            if row.updated_on + timezone.timedelta(minutes=settings.OTP_TIMESTAMP) < timezone.now():
                return False
            row.delete()
            return True
        except self.model.DoesNotExist:
            return False

    # def create_or_update(self, user, otp):
    #     try:
    #         row = self.get(user=user)
    #         row.otp = otp
    #         row.save()
    #         return row
    #     except self.model.DoesNotExist:
    #         return self.create(user=user, otp=otp)
