from celery import Celery

from controller.config import init_config

# Initialize Config
config = init_config()


def make_celery():
    is_test = config.environment == "testing"
    broker_url = "memory://" if is_test else config.redis_url
    backend_url = "cache+memory://" if is_test else config.redis_url

    app = Celery(
        "sentinel",
        broker=broker_url,
        backend=backend_url,
        include=["controller.tasks", "controller.tasks_retention"],
    )

    # Retention interval from env (default 6 hours)
    import os

    retention_interval = int(os.getenv("RETENTION_INTERVAL_HOURS", "6")) * 3600

    app.conf.update(
        task_always_eager=config.environment == "testing",
        task_eager_propagates=config.environment == "testing",
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        beat_schedule={
            "prune-old-data": {
                "task": "controller.tasks_retention.prune_old_data",
                "schedule": retention_interval,
            },
        },
    )

    return app


celery = make_celery()

if __name__ == "__main__":
    celery.start()
