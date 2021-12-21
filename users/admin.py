from django.contrib import admin

from users.models import (
    Address,
    ResetPassword,
    UnitOfHistory,
    User,
    UserDeviceToken,
    UserOTP,
    UserSocialAccount,
)

admin.site.register(UnitOfHistory)
admin.site.register(Address)
admin.site.register(ResetPassword)
admin.site.register(UserSocialAccount)
admin.site.register(UserDeviceToken)
admin.site.register(UserOTP)


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    model = User
    list_display = [
        'username', 'is_active', 'email', 'is_email_verified', 'phone', 'is_phone_verified', 'is_staff', 'is_superuser'
    ]
