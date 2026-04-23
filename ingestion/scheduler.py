import logging
from contextlib import contextmanager
from datetime import timedelta
from io import StringIO

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from django.core.management import call_command
from django.utils import timezone

log = logging.getLogger(__name__)


@contextmanager
def _capture_logs(name="ingestion"):
    #attach a temporary handler to the ingestion logger tree and return a
    #buffer holding every message emitted inside the with block
    buf = StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(logging.Formatter("%(message)s"))
    target = logging.getLogger(name)
    target.addHandler(h)
    try:
        yield buf
    finally:
        target.removeHandler(h)

#holds the scheduler after start_scheduler() creates it. stays None until
#then, and start_scheduler() refuses to make a second one.
_scheduler = None

#how long one period is for each frequency, used only to detect missed runs
_FREQUENCY_DELTA = {
    "every_6h": timedelta(hours=6),
    "every_12h": timedelta(hours=12),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}


def _build_trigger(task):
    #turn a ScheduledTask row into a trigger. IntervalTrigger fires every N
    #hours from now; CronTrigger fires at a specific wall clock time.
    h = task.time_of_day.hour
    m = task.time_of_day.minute

    if task.frequency == "every_6h":
        return IntervalTrigger(hours=6)

    if task.frequency == "every_12h":
        return IntervalTrigger(hours=12)

    if task.frequency == "daily":
        return CronTrigger(hour=h, minute=m)

    if task.frequency == "weekly":
        dow = task.day_of_week if task.day_of_week is not None else 0
        return CronTrigger(day_of_week=dow, hour=h, minute=m)

    if task.frequency == "monthly":
        dom = task.day_of_month or 1
        return CronTrigger(day=dom, hour=h, minute=m)

    return CronTrigger(hour=h, minute=m)


def _is_overdue(task, now):
    #never run, or last run is older than one full period
    delta = _FREQUENCY_DELTA.get(task.frequency)
    if delta is None:
        return False
    if task.last_run is None:
        return True
    return (now - task.last_run) >= delta


def _register_tasks(scheduler):
    #register every enabled task as a recurring job. replace_existing=True
    #makes this safe to call every time the admin form is saved.
    from ingestion.models import ScheduledTask

    for task in ScheduledTask.objects.filter(is_enabled=True):
        trigger = _build_trigger(task)
        scheduler.add_job(
            _run_task,
            trigger=trigger,
            args=[task.pk],
            id=f"task_{task.pk}",
            replace_existing=True,
        )


def _queue_catchup(scheduler):
    #queue a single immediate run for any overdue task.
    #boot only. running this on save would fire every overdue job again
    #each time the user clicks Save.
    from ingestion.models import ScheduledTask

    now = timezone.now()
    for task in ScheduledTask.objects.filter(is_enabled=True):
        if _is_overdue(task, now):
            scheduler.add_job(
                _run_task,
                trigger=DateTrigger(run_date=now),
                args=[task.pk],
                id=f"catchup_{task.pk}",
                replace_existing=True,
            )
            log.info("Catch-up scheduled: %s (last_run=%s)", task.command, task.last_run)


def _run_task(task_id):
    #APScheduler calls this on a worker thread when a trigger fires.
    #takes an int id, not an ORM object, because ORM instances are not
    #safe to share across threads. we fetch a fresh row here.
    from ingestion.models import ScheduledTask

    try:
        task = ScheduledTask.objects.get(pk=task_id)
    except ScheduledTask.DoesNotExist:
        log.warning("ScheduledTask %s no longer exists, skipping", task_id)
        return

    log.info("Scheduler firing: %s", task.command)

    try:
        args = task.args_json or {}
        #capture the command's own log output so we can show its tail on the card
        with _capture_logs() as buf:
            call_command(task.command, **args)
        task.last_status = "success"
        task.last_message = buf.getvalue()[-500:]
    except Exception as exc:
        task.last_status = "error"
        task.last_message = str(exc)[:500]
        log.exception("Scheduled command %s failed", task.command)

    task.last_run = timezone.now()
    task.save(update_fields=["last_run", "last_status", "last_message"])


def start_scheduler():
    #build the scheduler and register every enabled task. called once at boot.
    global _scheduler

    if _scheduler is not None:
        return

    #bind cron triggers to the project timezone so a picker value like 02:00
    #means 2 AM local, not UTC
    from django.conf import settings as dj_settings
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(dj_settings.TIME_ZONE)

    #BackgroundScheduler runs its own dispatcher thread so it never blocks
    #a web request. daemon=True lets Python exit cleanly on Ctrl+C instead
    #of waiting for that thread to stop on its own.
    _scheduler = BackgroundScheduler(daemon=True, timezone=tz)
    _register_tasks(_scheduler)
    _queue_catchup(_scheduler)
    _scheduler.start()
    log.info("APScheduler started (tz=%s) with %d jobs", tz, len(_scheduler.get_jobs()))


def reload_scheduler():
    #called after the admin form is saved. wipes every job and rebuilds
    #from the database. does not run catchup, so saving never fires a job.
    global _scheduler

    if _scheduler is None:
        start_scheduler()
        return

    _scheduler.remove_all_jobs()
    _register_tasks(_scheduler)
    log.info("Scheduler reloaded with %d jobs", len(_scheduler.get_jobs()))
