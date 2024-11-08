from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'My custom management command'

    def handle(self, *args, **options):
        # Command logic goes here
        self.stdout.write(self.style.SUCCESS('Command executed successfully'))