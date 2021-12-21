from logging import getLogger

import graphene
from django.contrib.auth import get_user_model
from django.utils import timezone
from graphene_django.forms.mutation import DjangoFormMutation

# from graphene_file_upload.scalars import Upload
from graphql import GraphQLError

from backend.permissions import is_admin_user
from notifications.forms import NotificationForm
from notifications.models import Notification
from notifications.object_types import NotificationType
from notifications.tasks import send_user_bulk_notification
from users.models import UserDeviceToken

User = get_user_model()


class NotificationMutation(DjangoFormMutation):
    """
        Create and update notification information through a form including some default fields.
    """
    success = graphene.Boolean()
    message = graphene.String()
    notification = graphene.Field(NotificationType)

    class Meta:
        form_class = NotificationForm

    @is_admin_user
    def mutate_and_get_payload(self, info, **input):
        user = info.context.user
        form = NotificationForm(data=input)
        object_id = None
        if form.data.get('object_id'):
            object_id = form.data['object_id']
            obj = Notification.objects.get(id=object_id)
            form = NotificationForm(data=input, instance=obj)
        if form.is_valid():
            users = form.cleaned_data['users']
            del form.cleaned_data['object_id'], form.cleaned_data['users']
            form.cleaned_data['creator'] = user
            if not form.cleaned_data['scheduled_on']:
                form.cleaned_data['scheduled_on'] = timezone.now()
            obj, created = Notification.objects.update_or_create(id=object_id, defaults=form.cleaned_data)
            if users != obj.users.all():
                for usr in users:
                    obj.users.add(usr)
            if obj.scheduled_on.replace(second=0, microsecond=0) == timezone.now().replace(second=0, microsecond=0):
                obj.sent_on = obj.scheduled_on
                obj.save()
                tokens = UserDeviceToken.objects.filter(user__in=obj.users.all())
                tokens = list(set(list(tokens.values_list('device_token', flat=True).distinct())))
                if tokens:
                    send_user_bulk_notification.delay(obj.title, obj.message, tokens, obj.notification_type)
                else:
                    getLogger().error("No user device tokens found.")
            elif obj.scheduled_on.replace(second=0, microsecond=0) > timezone.now().replace(second=0, microsecond=0):
                obj.sent_on = None
                obj.save()
        else:
            error_data = {}
            for error in form.errors:
                for err in form.errors[error]:
                    error_data[error] = err
            raise GraphQLError(
                message="Invalid input request.",
                extensions={
                    "errors": error_data,
                    "code": "invalid_input"
                }
            )
        return NotificationMutation(
            success=True, message=f"Successfully {'added' if created else 'updated'}", notification=obj
        )


class Mutation(graphene.ObjectType):
    """
        All the notification-mutations put here to be called from graphql-playground by specific names.
    """
    notification_mutation = NotificationMutation.Field()
