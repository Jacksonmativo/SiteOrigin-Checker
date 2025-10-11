from celery import Celery

celery_app = Celery(
    "site_checker",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

celery_app.autodiscover_tasks(
    [
        'backend.whois_checker',
        'backend.ssl_checker',
        'backend.score_calculator',
    ]
)  # Ensure tasks are discovered

# Note: Ensure Redis server is running locally on the default port 6379
# You can start a Redis server using the command: redis-server.
