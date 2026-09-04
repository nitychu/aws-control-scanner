import os
import yaml

_PATH = os.path.join(os.path.dirname(__file__), "mappings.yaml")

with open(_PATH) as f:
    CONTROLS = yaml.safe_load(f)


def get(control_id):
    """Return the control definition, or a placeholder if unmapped."""
    return CONTROLS.get(control_id, {
        "title": "Unmapped control",
        "severity": "UNKNOWN",
        "frameworks": {},
    })
