import time

from django.core.management.base import BaseCommand
from django.utils import timezone

from ops.models import ScanRun, ScanSchedule
from ops.services import run_scan_pipeline


class Command(BaseCommand):
    help = (
        "Run due account scan schedules. Single pass by default; use --loop to "
        "keep polling (for the docker-compose scheduler service or systemd)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--loop",
            action="store_true",
            help="Keep running and poll for due schedules.",
        )
        parser.add_argument(
            "--poll-seconds",
            type=int,
            default=60,
            help="Seconds between polls when --loop is set (default 60).",
        )

    def handle(self, *args, **options):
        if not options["loop"]:
            executed = self.run_due_schedules()
            self.stdout.write(self.style.SUCCESS(f"Executed {executed} due schedule(s)."))
            return
        self.stdout.write("Scheduler loop started. Press Ctrl+C to stop.")
        while True:
            executed = self.run_due_schedules()
            if executed:
                self.stdout.write(f"Executed {executed} schedule(s) at {timezone.now():%H:%M:%S}.")
            time.sleep(options["poll_seconds"])

    def run_due_schedules(self) -> int:
        now = timezone.now()
        executed = 0
        due = ScanSchedule.objects.select_related("account").filter(enabled=True)
        for schedule in due:
            if not schedule.is_due(now):
                continue
            scan_run = run_scan_pipeline(schedule.account)
            schedule.mark_ran(scan_run.status)
            executed += 1
            style = (
                self.style.SUCCESS
                if scan_run.status == ScanRun.Status.SUCCESS
                else self.style.ERROR
            )
            self.stdout.write(
                style(f"{schedule.account.name}: {scan_run.status} ({scan_run.id})")
            )
        return executed
