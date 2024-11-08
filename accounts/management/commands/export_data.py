from django.core.management.base import BaseCommand
from accounts.models import CallRecording
import csv
class Command(BaseCommand):
    help = 'Export data from MyModel'

    def handle(self, *args, **options):
        data = CallRecording.objects.all().values('user', 'metadata', 'encrypted','encrypted_aes_key','iv')
        with open('data.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerow(['user', 'metadata', 'encrypted','encrypted_aes_key','iv'])
            for row in data:
                writer.writerow(row.values())
        self.stdout.write(self.style.SUCCESS('Data exported successfully'))