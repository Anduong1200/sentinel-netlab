import logging
import os
from functools import wraps

from flask import Flask, g, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

from controller.config import init_config

# Validation
try:
    from pydantic import ValidationError
except ImportError:
    raise ImportError("Pydantic is strictly required for the Controller.") from None

PYDANTIC_AVAILABLE = True

# Initialize Config
config = init_config()

# Logging
from common.observability.logging import configure_logging  # noqa: E402

# Configure Logging (JSON + Correlation)
debug_mode = config.debug
log_level = "DEBUG" if debug_mode else "INFO"
logger = configure_logging("controller", level=log_level, json_mode=True)
logger = logging.getLogger(__name__)

# DB
db = SQLAlchemy()

# Limiter
from flask_limiter import Limiter  # noqa: E402
from flask_limiter.util import get_remote_address  # noqa: E402

# Create global limiter instance
# key_func is required.
limiter = Limiter(
    key_func=get_remote_address, default_limits=["200 per day", "50 per hour"]
)


# Validator Decorator
def validate_json(model_class):
    """Decorator to validate request JSON with Pydantic"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            try:
                data = request.get_json()
                validated = model_class(**data)
                g.validated_data = validated
            except ValidationError as e:
                return (
                    jsonify({"error": "Validation failed", "details": e.errors()}),
                    400,
                )
            except Exception as e:
                return jsonify({"error": f"Invalid JSON: {str(e)}"}), 400

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.security.secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = config.database.url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
    )  # 16MB default

    CORS(app, resources={r"/api/*": {"origins": config.security.cors_origins}})
    db.init_app(app)
    limiter.init_app(app)

    return app
