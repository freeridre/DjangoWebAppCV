from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordResetForm
from django.contrib.auth.validators import UnicodeUsernameValidator, ASCIIUsernameValidator
from UserHandler.models import Account
from django.utils.safestring import mark_safe
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import re

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(max_length=60, help_text="Required to add unique email address.")
    username = forms.CharField(max_length=128, help_text="Please, choose a unique username.", validators=[
                               UnicodeUsernameValidator, ASCIIUsernameValidator])
    password1 = forms.CharField(max_length=128,
                                help_text=mark_safe("Your password can’t be too similar to your other personal information.</br> \
                                    Your password must contain at least 8 characters.</br> \
                                    Your password can’t be a commonly used password.</br> \
                                    Your password can’t be entirely numeric.</br>")
                                )
    password2 = forms.CharField(max_length=128,
                                help_text="Enter the same password as before, for verification."
                                )

    class Meta:
        model = Account
        fields = ("email", "username", "password1", "password2")

class PasswordResetForm(PasswordResetForm):
    email = forms.EmailField(max_length=60)


class CustomPasswordResetForm(forms.ModelForm):
    new_password1 = forms.CharField(max_length=128,
                                help_text=mark_safe("Your password can’t be too similar to your other personal information.</br> \
                                    Your password must contain at least 8 characters.</br> \
                                    Your password can’t be a commonly used password.</br> \
                                    Your password can’t be entirely numeric.</br>")
                                )
    new_password2 = forms.CharField(max_length=128,
                                help_text="Enter the same password as before, for verification."
                                )

    class Meta:
        model = Account
        fields = ("new_password1", "new_password2")

    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')

        # validate the password using Django's built-in validators
        try:
            validate_password(password)
        except ValidationError as e:
            raise forms.ValidationError(e)

        # validate the password using a regular expression pattern
        pattern = r'^(?=.*\d)(?=.*[a-zA-Z]).{8,}$'
        if not re.match(pattern, password):
            raise forms.ValidationError(
                "Password must be at least 8 characters long and contain both letters and numbers.")

        return password

    def clean(self):
        cleaned_data = super().clean()
        new_password1 = cleaned_data.get("new_password1")
        new_password2 = cleaned_data.get("new_password2")

        if new_password1 and new_password2 and new_password1 != new_password2:
            raise forms.ValidationError(
                "The passwords you entered do not match.")

        return cleaned_data
