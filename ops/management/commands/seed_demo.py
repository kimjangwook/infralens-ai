from django.core.management.base import BaseCommand

from ops.services import seed_demo_data


class Command(BaseCommand):
    help = "Create a demo cloud account, findings, and briefing."

    def handle(self, *args, **options):
        account = seed_demo_data()
        self.stdout.write(self.style.SUCCESS(f"Seeded demo account: {account.name}"))

