from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from controller.config import init_config
import os
import logging
from functools import wraps
from flask import request, g, jsonify

# Validation
try:
    from pydantic import BaseModel, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

# Initialize Config
config = init_config()

# Logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# DB
db = SQLAlchemy()

# Limiter
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False
    
    # Dummy
    class Limiter:
        def __init__(self, key_func=None, app=None, default_limits=None, storage_uri=None): pass
        def limit(self, limit_string):
            def decorator(f): return f
            return decorator
    def get_remote_address(): return "127.0.0.1"

# Validator Decorator
def validate_json(model_class):
    """Decorator to validate request JSON with Pydantic"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not PYDANTIC_AVAILABLE:
                return f(*args, **kwargs)

            try:
                data = request.get_json()
                validated = model_class(**data)
                g.validated_data = validated
            except ValidationError as e:
                return jsonify({"error": "Validation failed", "details": e.errors()}), 400
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
    
    CORS(app)
    db.init_app(app)
    
    return app
