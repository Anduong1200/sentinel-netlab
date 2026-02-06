#!/usr/bin/env python3
"""
Generate OpenAPI schema from Pydantic models and Flask routes.
"""
import yaml
from pydantic.schema import schema

from common.contracts import Alert, NormalizedFrame, TelemetryBatch


def generate_openapi():
    # 1. Base Open API Structure
    openapi = {
        "openapi": "3.0.0",
        "info": {
            "title": "Sentinel NetLab API",
            "version": "1.0.0",
            "description": "API for Sentinel NetLab Controller"
        },
        "components": {
            "schemas": {}
        },
        "paths": {}
    }

    # 2. Extract Pydantic Schemas
    # Note: Modern Pydantic (v2) uses model_json_schema, v1 uses schema()
    # Assuming v1 compat or v2:
    try:
        # Pydantic V2
        # from pydantic.json_schema import models_json_schema # Unused
        top_models = [(TelemetryBatch, "TelemetryBatch"), (NormalizedFrame, "NormalizedFrame"), (Alert, "Alert")]
        # This is complex in V2, simplified approach:
        for model, name in top_models:
            openapi["components"]["schemas"][name] = model.model_json_schema()
    except ImportError:
        # Pydantic V1
        top_models = [TelemetryBatch, NormalizedFrame, Alert]
        definitions = schema(top_models).get("definitions", {})
        openapi["components"]["schemas"] = definitions

    # 3. Add to paths (Manual or Introspection)
    # Ideally, use an extension like flask-openapi3 or apispec, but for now we dump the models
    # as the "Source of Truth" for the payload structure.

    print(yaml.dump(openapi, sort_keys=False))

if __name__ == "__main__":
    generate_openapi()
