from django.core.management.base import BaseCommand, CommandError

from ops.models import CloudAccount
from ops.scanners import run_scan
from ops.services import generate_daily_briefing


class Command(BaseCommand):
    help = "Run a read-only scan for one cloud account."

    def add_arguments(self, parser):
        parser.add_argument("account_id")

    def handle(self, *args, **options):
        try:
            account = CloudAccount.objects.get(id=options["account_id"])
        except CloudAccount.DoesNotExist as exc:
            raise CommandError("Cloud account not found.") from exc

        scan_run = run_scan(account)
        if scan_run.status == scan_run.Status.FAILED:
            raise CommandError(scan_run.error_message)
        generate_daily_briefing(account)
        self.stdout.write(self.style.SUCCESS(f"Scan finished: {scan_run.id}"))

