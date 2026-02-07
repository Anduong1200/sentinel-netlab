from celery import Celery

from controller.config import init_config

# Initialize Config
config = init_config(strict_production=False)


def make_celery():
    app = Celery(
        "sentinel",
        broker=config.redis_url,
        backend=config.redis_url,
        include=["controller.tasks"],
    )

    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
    )

    return app


celery = make_celery()

if __name__ == "__main__":
    celery.start()
