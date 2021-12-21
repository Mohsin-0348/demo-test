# at w3gym/backend/users/views.py
import json

import folium
import geocoder
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic import View

User = get_user_model()


def index(request):
    context = {}
    # create map object
    m = folium.Map(location=[20, -12], zoom_start=2)

    address = 'UK'
    if request.method == 'POST':
        address = request.POST.get('address')
        print(address)
    location = geocoder.osm(address)
    if location:
        latitude = location.lat
        longitude = location.lng
        country = location.country
        print(latitude, longitude, country)
        folium.Marker([latitude, longitude], tooltip="Click for more", popup=address).add_to(m)
        if (latitude > 0 and abs(settings.DEFAULT_LATITUDE - latitude) < 0.0002) and \
                (longitude > 0 and abs(settings.DEFAULT_LONGITUDE - longitude) < 0.0002):
            context['validity'] = "valid"
        else:
            context['validity'] = "invalid"
    else:
        context['not_found'] = "Location not found"
    folium.Marker([settings.DEFAULT_LATITUDE, settings.DEFAULT_LONGITUDE], tooltip="Click for more", popup="Default Location").add_to(m)
    # get html representation of map object
    m = m._repr_html_()
    context['m'] = m
    context['address'] = address
    return render(request, 'index.html', context)


class EmailVerify(View):

    def get(self, request, token):
        if token:
            try:
                user = User.objects.get(activation_token=token)
                user.activation_token = None
                user.is_email_verified = True
                user.save()
                return HttpResponse("<center>Verified Successful</center>")
            except User.DoesNotExist:
                return HttpResponse("<center>Wrong or expired token!</center>")


def test_notification(request):
    return render(request, 'test_notification.html')


def showFirebaseJS(request):
    data = 'importScripts("https://www.gstatic.com/firebasejs/8.2.0/firebase-app.js");' \
           'importScripts("https://www.gstatic.com/firebasejs/8.2.0/firebase-messaging.js"); ' \
           'var firebaseConfig = {' \
           '        apiKey: "AIzaSyBnmD2URVN8pqTYuW-xgPsvMvN-2v3ocmg",' \
           '        authDomain: "test-my-app-a433c.firebaseapp.com",' \
           '        projectId: "test-my-app-a433c",' \
           '        storageBucket: "test-my-app-a433c.appspot.com",' \
           '        messagingSenderId: "401577186421",' \
           '        appId: "1:401577186421:web:722211e07d85a17566543c",' \
           '        measurementId: "G-HN5RKM9E5Z"' \
           ' };' \
           'firebase.initializeApp(firebaseConfig);' \
           'const messaging=firebase.messaging();' \
           'messaging.setBackgroundMessageHandler(function (payload) {' \
           '    console.log(payload);' \
           '    const notification=JSON.parse(payload);' \
           '    const notificationOption={' \
           '        body:notification.body,' \
           '        icon:notification.icon' \
           '    };' \
           '    return self.registration.showNotification(payload.notification.title,notificationOption);' \
           '});'

    return HttpResponse(data, content_type="text/javascript")


def send_notification(registration_ids, message_title, message_desc):
    fcm_api = settings.FCM_KEY
    url = settings.FCM_URL

    headers = {
        "Content-Type": "application/json",
        "Authorization": 'key=' + fcm_api}

    payload = {
        "registration_ids": registration_ids,
        "priority": "high",
        "notification": {
            "body": message_desc,
            "title": message_title,
            "image": "https://i.ytimg.com/vi/m5WUPHRgdOA/hqdefault.jpg?sqp=-oaymwEXCOADEI4CSFryq4qpAwkIARUAAIhCGAE=&rs=AOn4CLDwz-yjKEdwxvKjwMANGk5BedCOXQ",
            "icon": "https://yt3.ggpht.com/ytc/AKedOLSMvoy4DeAVkMSAuiuaBdIGKC7a5Ib75bKzKO3jHg=s900-c-k-c0x00ffffff-no-rj",

        }
    }

    result = requests.post(url, data=json.dumps(payload), headers=headers)
    print(result.json())
    return result.json()


def send(request):
    if request.method == "POST":
        context = {}
        result = send_notification([request.POST.get('token').strip()], request.POST.get('title'),
                                   request.POST.get('body'))
        context["token"] = request.POST.get('token')
        if result['success']:
            context['success'] = "Notification was sent"
        else:
            context['failed'] = "Failed to send notification"
        context['results'] = result['results']
        return render(request, 'send_notification.html', context)

    return render(request, 'send_notification.html')
