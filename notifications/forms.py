from django import forms

from notifications.models import Notification


class NotificationForm(forms.ModelForm):
    object_id = forms.CharField(max_length=64, required=False)

    class Meta:
        model = Notification
        fields = ('title', 'message', 'notification_type', 'users', 'scheduled_on')
