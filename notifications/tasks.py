# third party imports
from logging import getLogger

import django.contrib.auth
from django.utils import timezone

# local imports
from backend.celery import app
from backend.fcm import FCMNotification as ExFCMNotification
from notifications.models import Notification
from users.models import UserDeviceToken

User = django.contrib.auth.get_user_model()


def send_notification_and_save(user_id, title, message, n_type):
    user = User.objects.get(id=user_id)
    token = getattr(user, 'userdevicetoken', None)
    notification = Notification.objects.create(
        # user=instance.sender,
        title=title,
        message=message,
        notification_type=n_type,
        object_id=user_id,
    )
    notification.users.add(user)
    if token:
        send_user_notification.delay(token.device_token, notification.title, notification.message,
                                     notification.notification_type)
    else:
        getLogger().error("No user device token found.")


@app.task
def send_user_notification(token, title, message, notification_type):
    """
        send notification to single user
    """
    fcm = ExFCMNotification(
        title=title,
        message=message,
        token=token,
        notification_type=notification_type
    )
    try:
        fcm.send_notification()
    except Exception as e:
        getLogger().error(e)


def divide_chunks(ls, n):
    """
        take a list and return the list to n length
    """
    for i in range(0, len(ls), n):
        yield ls[i: i + n]


@app.task
def send_bulk_notification(title, msg, tokens, notification_type):
    """
        divide recipients into chunks for limit 500
    """
    for chunk in divide_chunks(tokens, 500):
        send_chunk_notifications.delay(title, msg, chunk, notification_type)


@app.task
def send_chunk_notifications(title, msg, tokens, notification_type):
    """
        send notification to multiple users by their tokens
    """
    print("Start", timezone.now(), flush=True)
    try:
        ExFCMNotification(title, msg, None, notification_type).send_bulk_notification(tokens)
    except Exception as e:
        getLogger().error(f"{e}")
    print("End", timezone.now(), flush=True)


@app.task
def send_user_bulk_notification(title, message, tokens, notification_type):
    """
        take required arguments and proceed for sending notification
    """
    print(tokens)
    send_bulk_notification(title, message, tokens, notification_type)


@app.task
def send_scheduled_notifications():
    """
        check for notifications if scheduled and not sent
    """
    now = timezone.now()
    start = now.replace(second=0, microsecond=0)
    end = now.replace(second=59)
    notifications = Notification.objects.filter(scheduled_on__gte=start, scheduled_on__lte=end, sent_on=None)
    print(f"Notifications {notifications}")
    for item in notifications:
        users = item.users.all()
        user_tokens = UserDeviceToken.objects.filter(user__in=users)
        tokens = list(set(list(user_tokens.values_list('device_token', flat=True).distinct())))
        send_user_bulk_notification.delay(item.title, item.message, tokens, item.notification_type)
        item.sent_on = now
        item.save()
