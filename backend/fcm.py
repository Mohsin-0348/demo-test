# third party imports
import uuid
from logging import getLogger

import firebase_admin
from django.conf import settings
from firebase_admin import credentials
from pyfcm import FCMNotification as PYFCMNotification

cred = credentials.Certificate(settings.FIREBASE_CONFIG_PATH)
firebase_admin.initialize_app(cred)


class FCMNotification:

    def __init__(self, title, message, token, notification_type="", sound=True, image="", pending=1, id=None):
        """
            Initialise some default fields.
        """
        self.push_service = PYFCMNotification(api_key=settings.FCM_KEY)
        self.title = title
        self.message = message
        self.token = token
        self.notification_type = notification_type
        self.play_sound = sound
        self.pending = pending
        self.object_id = id
        self.fcm_key = settings.FCM_KEY
        self.image = image

    def get_payload(self):
        """
            Define payload-data by default fields.
        """
        data = {
            "type": self.notification_type,
            "details": self.message,
            "title": self.title,
            "message": self.message,
            "image": self.image,
            "object_id": self.object_id,
            "sound": "default",
            "notificationId": str(uuid.uuid4()),
            "show_in_foreground": True,
            "priority": "high",
            "actions": "com.w3gym",
            "color": "red",
            "autoCancel": True,
            "channelId": "fcm_FirebaseNotifiction_default_channel",
            "largeIcon": "ic_launcher",
            "lights": True,
            "icon": "ic_notif",
            "playSound": self.play_sound,
            "subText": self.pending,
            "vibrate": self.play_sound,
            "tag": self.notification_type,
            "group": self.notification_type,
            "groupSummary": True,
            "ongoing": False,
            "visibility": "private",
            "ignoreInForeground": False,
            "invokeApp": True,
            "subtitle": self.pending,
            'soundName': "default",
            'number': 10,

        }
        return data

    def send_notification(self):
        """
            Send notification to a single device through some default fields.
        """
        data = self.get_payload()
        result = self.push_service.notify_single_device(
            registration_id=self.token,
            message_title=self.title,
            message_body=self.message,
            data_message=data,
            sound='default'
        )
        if not result.get('success'):
            # print("Error", result, flush=True)
            getLogger().error("Error", result)

    def send_bulk_notification(self, tokens):
        """
            Send notification to multiple devices by providing clean-token ids
            through some default fields.
        """
        tokens = self.push_service.clean_registration_ids(tokens)
        if tokens:
            data = self.get_payload()
            result = self.push_service.notify_multiple_devices(
                registration_ids=tokens,
                message_title=self.title,
                message_body=self.message,
                data_message=data,
                sound='default'
            )
            if not result.get('success'):
                # print("Error", result, flush=True)
                getLogger().error("Error", result)
