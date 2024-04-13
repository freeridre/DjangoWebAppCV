from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from enum import Enum
class StatusChoices(models.TextChoices):
    CREATED = 'CREATED', _('Created')
    ACTIVATED = 'ACTIVATED', _('Activated')
    REMOVED = 'REMOVED', _('Removed')
    UPDATED = 'UPDATED', _('Updated')
    REJECTED = 'REJECTED', _('Rejected')

class AccessTiers(models.TextChoices):
    STANDARD = 'STANDARD', _('STANDARD')
    ENHANCED = 'ENHANCED', _('ENHANCED')
    ADVANCED = 'ADVANCED', _('ADVANCED')
    ELITE = 'ELITE', _('ELITE')

# python manage.py makemigrations
# python manage.py migrate
class AccountManager(BaseUserManager):
    def create_user(self, email: str, username: str, password=None):
        if not username:
            raise ValueError("User must have an unique username!")
        if not email:
            raise ValueError("User must have an unique email address!")
        if not password:
            raise ValueError("User must have a password")

        user = self.model(
            email=self.normalize_email(email),
            username=username
        )

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, username, password=None):
        user = self.create_user(
            email=self.normalize_email(email),
            username=username,
            password = password
        )

        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)

        return user
class Account(AbstractBaseUser):
    token_version = models.PositiveIntegerField(default=1)
    email = models.EmailField(
        verbose_name="email",
        max_length=60,
        unique=True)
    username = models.CharField(
        verbose_name="username",
        max_length=150,
        unique=True,
    )
    device_id = models.CharField(max_length=255, null=True, blank=True)
    device_type = models.CharField(max_length=10, null=True, blank=True)  # iOS or Android
    push_token = models.CharField(max_length=255, null=True, blank=True)
    date_joined = models.DateTimeField(
        verbose_name="date joined", auto_now_add=True)
    last_login = models.DateTimeField(
        verbose_name="last login", auto_now=True)
    
    is_admin = models.BooleanField(
        default=False)
    is_active = models.BooleanField(
        default=False)
    is_staff = models.BooleanField(
        default=False)
    is_superuser = models.BooleanField(
        default=False)

    first_name = models.CharField(
        verbose_name="first name", max_length=150, blank=False, null=True)
    last_name = models.CharField(
        verbose_name="last name", max_length=150, blank=False, null=True)
    has_pass = models.BooleanField(
        verbose_name="Pass", default=False, help_text="Shows True if the user has a pass.")
    pass_is_active = models.BooleanField(
        verbose_name="Pass_active", default=False, help_text="Shows that the pass is active or not.")
    date_pass_registered = models.DateTimeField(
        verbose_name='When the pass regisered with the phone.', null=True)
    date_pass_rejected = models.DateTimeField(
        verbose_name='when the pass rejected from the user.', null=True)
    authentication_device = models.CharField(
        max_length=128, verbose_name='device', null=True)
    authentication_device_id = models.CharField(
        max_length=128, unique=True, verbose_name='device', null=True)

    is_password_reset = models.BooleanField(default=False)

    USERNAME_FIELD = "username"
    # REQUIRED_FIELDS must contain all required fields on your user model,
    # but should not contain the USERNAME_FIELD or password as these fields
    # will always be prompted for.
    REQUIRED_FIELDS = ['email']

    objects = AccountManager()

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    def invalidate_reset_tokens(self):
        """
        This method delete the associated token of the actual user.
        """
        ResetPasswordToken.objects.filter(user=self).delete()

class PasswordHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class ResetPasswordToken(models.Model):
    user = models.ForeignKey(Account, on_delete=models.CASCADE)
    token = models.CharField(max_length=200, unique=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    def is_valid(self):
        if self.is_used:
            return False
        if timezone.now() > self.expires_at:
            return False
        return True

class DeletedUserLog(models.Model):
    deletedTime = models.DateTimeField(auto_now_add=True)
    username = models.CharField(
        verbose_name="username",
        max_length=150
    )
    email = models.EmailField(
        verbose_name="email",
        max_length=60
    )
    date_joined = models.DateTimeField(
        verbose_name="date joined")

    def __str__(self):
        return self.username

class GoogleWalletPass(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='google_wallet_passes')
    issuer_id = models.CharField(max_length=2000)
    class_suffix = models.CharField(max_length=2000)
    object_suffix = models.CharField(max_length=2000)
    pay_load = models.CharField(max_length=2000, default='')
    jwt_link = models.TextField()
    token = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=2000, choices=StatusChoices.choices, default=StatusChoices.CREATED)
    access_tier = models.CharField(max_length=100, choices=AccessTiers.choices, default=AccessTiers.STANDARD)

class AppleWalletPassAccountID(models.Model):
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='apple_wallet_passes')
    pass_id = models.BigIntegerField(unique=True)
    pay_load = models.CharField(max_length=2000, default='')
    date_created = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=2000, choices=StatusChoices.choices, default=StatusChoices.CREATED)
    date_updated = models.DateTimeField(auto_now=True)
    access_tier = models.CharField(max_length=100, choices=AccessTiers.choices, default=AccessTiers.STANDARD)
    def __str__(self):
        return f"Apple Wallet Pass Account ID for {self.account}"
