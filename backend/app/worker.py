from celery import Celery

from .config import settings
from .tasks import run_site_scan

celery_app = Celery("dera", broker=settings.redis_url, backend=settings.redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=30,
    task_soft_time_limit=25,
    broker_connection_retry_on_startup=True,
)


@celery_app.task(name="dera.scan_site", acks_late=True)
def scan_site_task(scan_id: str) -> None:
    run_site_scan(scan_id)
