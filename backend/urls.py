"""
    Define urls for all tenants to work individually.
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path
from django.views.decorators.csrf import csrf_exempt
from graphene_file_upload.django import FileUploadGraphQLView

from users.views import EmailVerify, index, send, showFirebaseJS, test_notification

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', index),
    path('graphql/', csrf_exempt(FileUploadGraphQLView.as_view(graphiql=True))),
    path('verify/<token>/', EmailVerify.as_view(), name='email_verify'),
    path('get-device-token/', test_notification),
    path('send-notification/', send),
    path('firebase-messaging-sw.js', showFirebaseJS, name="show_firebase_js"),
]

urlpatterns = urlpatterns + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns = urlpatterns + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
