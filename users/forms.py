from django import forms
from django.contrib.auth import get_user_model

from users.models import Address

User = get_user_model()


class UserRegistrationForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ("username", "email", "phone", "password")


class UserOTPRegistrationForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ("username", "phone", "password")


class AdminRegistrationForm(forms.ModelForm):
    super_user = forms.BooleanField(required=False)

    class Meta:
        model = User
        fields = ("username", "email", "password")


class UserUpdateForm(forms.ModelForm):

    class Meta:
        model = User
        fields = ("username", "email", "first_name", "last_name", "gender", "phone", "date_of_birth")


class AddressForm(forms.ModelForm):
    object_id = forms.CharField(max_length=8, required=False)

    class Meta:
        model = Address
        exclude = ('user',)
