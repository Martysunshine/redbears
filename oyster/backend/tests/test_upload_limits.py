from __future__ import annotations

import io

import pytest
from starlette.datastructures import UploadFile

from routers.artifacts import _read_bounded


@pytest.mark.asyncio
async def test_bounded_upload_rejects_before_copying_large_content():
    upload = UploadFile(file=io.BytesIO(b"123456"), filename="evidence.txt")
    with pytest.raises(Exception) as exc:
        await _read_bounded(upload, 5)
    assert getattr(exc.value, "status_code", None) == 413


@pytest.mark.asyncio
async def test_bounded_upload_rewinds_and_reads_allowed_content():
    upload = UploadFile(file=io.BytesIO(b"12345"), filename="evidence.txt")
    assert await _read_bounded(upload, 5) == b"12345"
