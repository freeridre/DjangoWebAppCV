from .models import PasswordHistory
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError


def validate_password_history(user, new_password):
    password_histories = PasswordHistory.objects.filter(
        user=user).order_by('-created_at')[:5]

    for history in password_histories:
        if check_password(new_password, history.password):
            raise ValidationError("You can't use your last 5 passwords.")


def password_history_archiver(user):
    # Keep only the last 5 password hashes for the user
    stored_passwords_count = PasswordHistory.objects.filter(user=user).count()
    if stored_passwords_count > 5:
        password_histories = PasswordHistory.objects.filter(
            user=user).order_by('-created_at')[5:]
        for history in password_histories:
            history.delete()
