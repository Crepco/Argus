"""Document / image metadata module (build-order step 10).

Input: document + image URLs discovered by dork_module and github_module.
Extracts PDF metadata (pypdf) and image EXIF/GPS (Pillow/exifread).

Guardrails: skip PDFs > 5MB and images > 2MB; delete every downloaded file
immediately after extraction; never persist binary content.
"""
from __future__ import annotations

from modules.base import BaseModule


class MetadataModule(BaseModule):
    name = "metadata_module"

    def __init__(self, urls: list[str]) -> None:
        self.urls = urls or []

    async def run(self) -> dict:
        if not self.urls:
            return self.clean()
        # TODO(step 10): stream-download with size cap -> pypdf doc info /
        #   Pillow EXIF+GPS -> flag author/company/device/coords -> unlink file.
        return self.clean()
