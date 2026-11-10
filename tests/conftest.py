from __future__ import annotations

import pytest

from ai_forensics.model import FULLTEXT_BYTES, ROW_CAP
from ai_forensics.ledger import CollectionHost


@pytest.fixture
def host(tmp_path):
    case = tmp_path / "case"
    host = CollectionHost(
        [tmp_path],
        include_subagents=True,
        row_cap=ROW_CAP,
        fulltext_bytes=FULLTEXT_BYTES,
    )
    host.open_db(case, reset=True)
    yield host
    host.close()
