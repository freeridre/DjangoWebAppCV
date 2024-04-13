from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from UserHandler.models import Account

class AccountAdmin(UserAdmin):
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "date_joined",
        "last_login",
        "is_admin",
        "is_staff",
        "has_pass",
        "pass_is_active"
    )
    search_field = (
        "username",
        "email",
        "first_name",
        "last_name",
        "date_joined",
        "last_login",
        "is_admin",
        "is_staff",
        "has_pass",
        "pass_is_active"
    )
    readonly_fields = (
        "date_joined",
        "last_login"
    )
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()

admin.site.register(Account, AccountAdmin)
