import time

from django.core.management.base import BaseCommand

from ops.models import BackgroundJob
from ops.services import claim_next_job, process_job


class Command(BaseCommand):
    help = (
        "Process queued background jobs (scans, daily reports). Single pass by "
        "default; use --loop for a long-running worker."
    )

    def add_arguments(self, parser):
        parser.add_argument("--loop", action="store_true", help="Keep polling for jobs.")
        parser.add_argument(
            "--poll-seconds",
            type=int,
            default=5,
            help="Seconds between polls when --loop is set (default 5).",
        )

    def handle(self, *args, **options):
        if not options["loop"]:
            processed = self.drain()
            self.stdout.write(self.style.SUCCESS(f"Processed {processed} job(s)."))
            return
        self.stdout.write("Worker loop started. Press Ctrl+C to stop.")
        while True:
            if not self.drain():
                time.sleep(options["poll_seconds"])

    def drain(self) -> int:
        processed = 0
        while True:
            job = claim_next_job()
            if job is None:
                return processed
            process_job(job)
            processed += 1
            style = (
                self.style.SUCCESS
                if job.status == BackgroundJob.Status.DONE
                else self.style.ERROR
            )
            self.stdout.write(style(f"{job.kind}: {job.status} ({job.id})"))
