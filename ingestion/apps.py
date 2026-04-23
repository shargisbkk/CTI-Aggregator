import os
import threading

from django.apps import AppConfig


class IngestionConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "ingestion"

    def ready(self):
        #runserver autoreloads in two processes. Only start the scheduler in
        #the child (RUN_MAIN is set) so jobs never fire twice.
        if os.environ.get("RUN_MAIN") == "true" or not os.environ.get("DJANGO_SETTINGS_MODULE"):
            #wait 2 seconds so the DB connection pool is ready before we query
            threading.Timer(2.0, self._safe_start).start()

    @staticmethod
    def _safe_start():
        try:
            from ingestion.scheduler import start_scheduler
            start_scheduler()
        except Exception:
            #on a fresh DB the scheduled_tasks table may not exist yet; keep
            #runserver alive so the user can run migrate
            import logging
            logging.getLogger(__name__).warning(
                "Scheduler skipped at boot (likely first run before migrations)"
            )
