from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from UserHandler.models import Account, DeletedUserLog

class Command(BaseCommand):
    help = "Deletes users who haven't activated their account within a day"

    def handle(self, *args, **kwargs):
        threshold_date = timezone.now() - timedelta(days=1)
        users_to_delete = Account.objects.filter(date_joined__lt=threshold_date, is_active=False)
        count = users_to_delete.count()
        
        # Log details for each user before deleting
        for user in users_to_delete:
            log_entry = DeletedUserLog(
                email=user.email,
                username=user.username,
                date_joined=user.date_joined,
            )
            log_entry.save()

        users_to_delete.delete()

        self.stdout.write(self.style.SUCCESS(f'Successfully deleted {count} unactivated user(s)'))


