
import graphene
from graphene_django.filter import DjangoFilterConnectionField

from backend.permissions import is_authenticated
from notifications.models import Notification, NotificationView
from notifications.object_types import NotificationType


class Query(graphene.ObjectType):
    """
        All queries for notifications are defined here through specific names.
    """
    notifications = DjangoFilterConnectionField(NotificationType)
    notification = graphene.Field(NotificationType, object_id=graphene.ID())

    @is_authenticated
    def resolve_notifications(self, info, **kwargs) -> object:
        """
            All notifications of users.
        """
        user = info.context.user
        if not user.is_admin:
            notifications = Notification.objects.filter(users=user)
            for obj in notifications:
                if not NotificationView.objects.filter(notification=obj, user=user):
                    obj, created = NotificationView.objects.get_or_create(
                        notification=obj,
                        user=user
                    )
                    obj.view_count = obj.view_count + 1
                    obj.save()
            return notifications
        return Notification.objects.all()

    @is_authenticated
    def resolve_notification(self, info, object_id, **kwargs) -> object:
        """
            Single notification view.
        """
        user = info.context.user
        if not user.is_admin:
            return Notification.objects.get(id=object_id, users=user)
        return Notification.objects.get(id=object_id)
