
import django_filters

from bases.filters import BaseFilters
from notifications.models import Notification, NotificationView


class NotificationFilters(BaseFilters):
    """
        Notification Filters are defined here
    """

    title = django_filters.CharFilter(
        field_name='title',
        lookup_expr='icontains'
    )
    notification_type = django_filters.CharFilter(
        field_name='notification_type',
        lookup_expr='exact'
    )

    class Meta:
        model = Notification
        fields = [
            'id',
            'title',
            'notification_type',
        ]


class NotificationViewFilters(BaseFilters):
    """
        Notification-viewed-by-user Filters are defined here
    """

    notification = django_filters.CharFilter(
        field_name='notification__title',
        lookup_expr='exact'
    )
    user = django_filters.CharFilter(
        field_name='user__username',
        lookup_expr='icontains'
    )

    class Meta:
        model = NotificationView
        fields = [
            'id',
            'notification',
            'user',
        ]
