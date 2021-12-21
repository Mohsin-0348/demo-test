
import graphene
from graphene_django import DjangoObjectType

from backend.count_connection import CountConnection
from notifications.filters import NotificationFilters, NotificationViewFilters
from notifications.models import Notification, NotificationView


class NotificationType(DjangoObjectType):
    """
        Notification type is defined here with default filtering,
        pagination, edge-node serialization and total-count.
    """
    object_id = graphene.ID()

    class Meta:
        model = Notification
        filterset_class = NotificationFilters
        interfaces = (graphene.relay.Node, )
        convert_choices_to_enum = False
        connection_class = CountConnection

    @staticmethod
    def resolve_object_id(self, info, **kwargs):
        return self.id


class NotificationViewType(DjangoObjectType):
    """
        Notification-viewed by user type is defined here with default filtering,
        pagination, edge-node serialization and total-count.
    """
    object_id = graphene.ID()

    class Meta:
        model = NotificationView
        filterset_class = NotificationViewFilters
        interfaces = (graphene.relay.Node, )
        convert_choices_to_enum = False
        connection_class = CountConnection

    @staticmethod
    def resolve_object_id(self, info, **kwargs):
        return self.id
