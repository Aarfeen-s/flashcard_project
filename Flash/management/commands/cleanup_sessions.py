from django.core.management.base import BaseCommand
from Flash.models import UserSession

class Command(BaseCommand):
    help = 'Cleanup old user sessions'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to keep sessions'
        )

    def handle(self, *args, **options):
        days = options['days']
        UserSession.cleanup_old_sessions(days=days)
        self.stdout.write(
            self.style.SUCCESS(f'Successfully cleaned up sessions older than {days} days')
        ) 