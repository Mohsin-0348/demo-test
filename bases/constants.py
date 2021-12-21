from django.db import models


class VerifyActionChoices(models.TextChoices):
    APPROVE = 'approve'
    REJECT = 'reject'


class ApprovalStatusChoice(models.TextChoices):
    PENDING = 'pending'
    APPROVED = 'approved'
    REJECTED = 'rejected'


class HistoryActions(models.TextChoices):
    USER_SIGNUP = 'user-signup'
    USER_LOGIN = 'user-login'
    USER_UPDATE = 'user-update'
    EMAIL_VERIFIED = 'email-verified'
    RESEND_ACTIVATION = 'resend-email-activation'
    PASSWORD_CHANGE = 'password-change'
    PASSWORD_RESET_REQUEST = 'password-reset-request'
    PASSWORD_RESET = 'password-reset'
    ACCOUNT_DEACTIVATE = 'account-deactivate'
    ADDRESS_UPDATE = 'address-update'
    SOCIAL_SINGUP = 'social-signup'
    SOCIAL_LOGIN = 'social-login'
    NEW_ADMIN_ADDED = 'new-admin-added'
    MEMBER_INFO_UPDATE = 'member-info-update'
    DELETE_FOOD = 'delete-food'
    EMPLOYEE_ADDED = 'employee-added'
    EMPLOYEE_UPDATED = 'employee-updated'
    PROFILE_PICTURE_UPLOAD = 'profile-picture-upload'
    DOCUMENT_UPLOADED = 'document-uploaded'
    USER_BLOCKED = 'user-blocked'
    USER_UNBLOCKED = 'user-unblocked'
    DOCUMENT_VERIFIED = 'document-verified'
    DOCUMENT_REJECTED = 'document-rejected'
    PROFILE_PICTURE_VERIFIED = 'profile-picture-verified'
    PROFILE_PICTURE_REJECTED = 'profile-picture-rejected'
    PERSONAL_SESSION_UPDATE = 'personal-session-update'
    NUTRITION_PLAN_UPDATE = 'nutrition-plan-update'
    CLASS_BOOKING_CANCELED = 'class-booking-canceled'
    CLASS_BOOKING_CONFIRMED = 'class-booking-confirmed'


class WeekDayChoice(models.TextChoices):
    MONDAY = 'monday'
    TUESDAY = 'tuesday'
    WEDNESDAY = 'wednesday'
    THURSDAY = 'thursday'
    FRIDAY = 'friday'
    SATURDAY = 'saturday'
    SUNDAY = 'sunday'
