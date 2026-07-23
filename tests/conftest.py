from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_sentry.models import ServerSurface


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "filesystem_server.json"


@pytest.fixture()
def filesystem_surface() -> ServerSurface:
    return ServerSurface.model_validate(json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))
