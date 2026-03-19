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
        include=["controller.tasks"],
    )

    app.conf.update(
        task_always_eager=config.environment == "testing",
        task_eager_propagates=config.environment == "testing",
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
