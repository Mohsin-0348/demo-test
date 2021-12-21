from django.contrib import admin

from notifications.models import Notification, NotificationView


class NotificationViewInline(admin.StackedInline):
    model = NotificationView


@admin.register(Notification)
class NotificationAmin(admin.ModelAdmin):
    inlines = [NotificationViewInline, ]
