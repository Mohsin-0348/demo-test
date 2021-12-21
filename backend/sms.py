
from random import randint

# from django.conf import settings

# from twilio.rest import Client


def generate_otp():
    otp = ''
    for x in range(4):
        otp += str(randint(1, 9))
    return otp


# def send_otp(phone, otp):
#     client = Client(settings.TWILIO_SID, settings.TWILIO_AUTH_TOKEN)
#     message = client.messages.create(
#         to="+8801701073917",  # phone,
#         from_=settings.TWILIO_NUMBER,
#         body=f"Your OTP is {otp} and valid for 2 minutes."
#     )
#     print(message.sid)
