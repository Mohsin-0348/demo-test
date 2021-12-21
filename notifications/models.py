from django.db import models

from bases.models import BaseModelWithOutId


class Notification(BaseModelWithOutId):
    title = models.TextField()
    message = models.TextField()
    notification_type = models.CharField(
        max_length=50
    )
    image = models.ImageField(
        blank=True,
        null=True,
        upload_to="notifications/images"
    )
    object_id = models.PositiveIntegerField(
        null=True,
        blank=True
    )
    users = models.ManyToManyField(
        'users.User'
    )
    creator = models.ForeignKey(
        'users.User',
        blank=True,
        null=True,
        on_delete=models.SET_NULL,
        related_name='created_notification'
    )
    scheduled_on = models.DateTimeField(
        null=True,
        blank=True
    )
    sent_on = models.DateTimeField(
        null=True,
        blank=True
    )
    seen_by = models.ManyToManyField(
        'users.User',
        through='NotificationView',
        related_name='seen_by_users'
    )


class NotificationView(models.Model):
    notification = models.ForeignKey(
        Notification,
        on_delete=models.CASCADE,
    )
    user = models.ForeignKey(
        'users.User',
        on_delete=models.CASCADE,
    )
    view_count = models.PositiveIntegerField(
        default=0
    )
