# at w3universal/backend/users/login_backends.py
from django.contrib.auth import authenticate, get_user_model
from django.db.models import Q
from django.utils import timezone
from graphql import GraphQLError

from bases.constants import HistoryActions
from bases.utils import email_checker

from .models import UnitOfHistory, UserSocialAccount

User = get_user_model()


def check_user(user, activate, phone=False) -> bool:
    """
        Check if user is admin or not and its email address is verified or not.
        Activate a deactivated account.
        and also check if user account is active or not.
    """
    if user.phone:
        if not user.is_admin and not user.is_phone_verified:
            raise GraphQLError(
                message="Please verify your phone number",
                extensions={
                    "message": "Please verify your phone number",
                    "code": "phone_not_verified"
                }
            )
    else:
        if not user.is_admin and not user.is_email_verified:
            raise GraphQLError(
                message="Please verify your email",
                extensions={
                    "message": "Please verify your email",
                    "code": "unverified_email"
                }
            )
    if not user.is_active and user.deactivation_reason:
        if activate:
            user.is_active = True
            user.deactivation_reason = None
            user.save()
        else:
            raise GraphQLError(
                message="Account is deactivated",
                extensions={
                    "message": "Account is deactivated",
                    "code": "account_not_active"
                }
            )
    elif not user.is_active:
        raise GraphQLError(
            message="Account is temporary blocked",
            extensions={
                "message": "Account is temporary blocked",
                "code": "account_blocked"
            }
        )
    return True


def signup(
    request,
    email,
    password,
    activate=False
) -> object:
    """
        Sign in user account by password and update last login time.
    """
    try:
        user = User.objects.filter(Q(email=email) | Q(phone=email)).last()
        if check_user(user, activate):
            user = authenticate(
                username=user.username,
                password=password
            )
            if not user:
                raise GraphQLError(
                    message="Invalid credentials",
                    extensions={
                        "message": "invalid credentials",
                        "code": "invalid_credentials"
                    }
                )
            user.last_login = timezone.now()
            user.save()
            UnitOfHistory.user_history(
                action=HistoryActions.USER_LOGIN,
                user=user,
                request=request
            )
            return user
    except User.DoesNotExist:
        raise GraphQLError(
            message="Email is not associate with any existing user.",
            extensions={
                "message": "Email is not associate with any existing user.",
                "code": "invalid_email"
            }
        )


def social_signup(
    request,
    social_type,
    social_id,
    email,
    activate=False,
    verification=False
):
    """
        Check social login for user account by social-id,  social-type and email address.
        Also check if email address provided or not and email is valid or not.
        Then check either existence of email address and its verification status also.
        A new user account will be created if there is no user account for this social account
        and also update last login time.
    """
    user_account = UserSocialAccount.objects.checkSocialAccount(
        social_id,
        social_type,
        email
    )
    if user_account:
        user = UserSocialAccount.objects.get(
            social_type=social_type,
            social_id=social_id
        ).user
        check_user(user, activate)
        user.last_login = timezone.now()
        user.save()
        UnitOfHistory.user_history(
            action=HistoryActions.SOCIAL_LOGIN,
            user=user,
            request=request
        )
        return user
    if not email:
        raise GraphQLError(
            message="Email is required",
            extensions={
                "message": "Email is required",
                "code": "email_not_found"
            }
        )
    elif not email_checker(email):
        raise GraphQLError(
            message="Invalid email address",
            extensions={
                "message": "Invalid email address",
                "code": "invalid_email"
            }
        )
    if email_checker(email):
        if User.objects.filter(email=email).exists():
            raise GraphQLError(
                message="Email is already exits",
                extensions={
                    "message": "Email is already exits",
                    "code": "duplicate_email"
                }
            )
    user = User.objects.create_user(email.split("@")[0] + str(timezone.now().date()), email)
    UserSocialAccount.objects.create(
        user=user,
        social_id=social_id,
        social_type=social_type
    )
    if verification:
        user.send_email_verification()
        raise GraphQLError(
            message="Please verify your email",
            extensions={
                "message": "Please verify your email",
                "code": "unverified_email"
            }
        )
    user.is_email_verified = True
    user.last_login = timezone.now()
    user.save()
    UnitOfHistory.user_history(
        action=HistoryActions.SOCIAL_SINGUP,
        user=user,
        request=request
    )
    return user
