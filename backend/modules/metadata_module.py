"""Document / image metadata module (build-order step 10).

Input: document + image URLs discovered by dork_module and github_module.
Extracts PDF metadata (pypdf) and image EXIF/GPS (Pillow).

Guardrails: skip PDFs > 5MB and images > 2MB; everything is processed from an
in-memory buffer (io.BytesIO) — nothing ever touches disk, so there is no file
to delete and no way to leak binary content beyond the current request.
"""
from __future__ import annotations

import io
import re
from typing import Optional

from modules.base import BaseModule, make_client

MAX_PDF_BYTES = 5 * 1024 * 1024
MAX_IMAGE_BYTES = 2 * 1024 * 1024
PDF_RE = re.compile(r"\.pdf(\?|$)", re.IGNORECASE)
IMAGE_RE = re.compile(r"\.(jpe?g|png)(\?|$)", re.IGNORECASE)


class MetadataModule(BaseModule):
    name = "metadata_module"

    def __init__(self, urls: list[str]) -> None:
        self.urls = urls or []

    async def run(self) -> dict:
        if not self.urls:
            return self.clean()

        findings: list[dict] = []
        sources: list[str] = []

        async with make_client(timeout=20) as client:
            for url in self.urls:
                if PDF_RE.search(url):
                    await self._scan_pdf(client, url, findings, sources)
                elif IMAGE_RE.search(url):
                    await self._scan_image(client, url, findings, sources)

        severity = self._severity(findings)
        return self.result(severity, findings, sources)

    async def _download(self, client, url: str, cap: int) -> Optional[bytes]:
        try:
            resp = await client.get(url)
            if resp.status_code != 200 or len(resp.content) > cap:
                return None
            return resp.content
        except Exception:
            return None

    async def _scan_pdf(self, client, url: str, findings: list[dict], sources: list[str]) -> None:
        data = await self._download(client, url, MAX_PDF_BYTES)
        if not data:
            return
        try:
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(data))
            meta = reader.metadata or {}
        except Exception:
            return

        fields = {}
        for key, label in (
            ("/Author", "author"),
            ("/Creator", "creator"),
            ("/Producer", "producer"),
            ("/Subject", "subject"),
            ("/CreationDate", "creation_date"),
        ):
            value = meta.get(key)
            if value:
                fields[label] = str(value)

        if fields:
            findings.append(
                {
                    "type": "pdf_metadata",
                    "category": "document metadata exposure",
                    "detail": f"PDF metadata reveals: {', '.join(f'{k}={v}' for k, v in fields.items())}.",
                    "fields": fields,
                    "source": url,
                }
            )
            sources.append(url)

    async def _scan_image(self, client, url: str, findings: list[dict], sources: list[str]) -> None:
        data = await self._download(client, url, MAX_IMAGE_BYTES)
        if not data:
            return
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            img = Image.open(io.BytesIO(data))
            exif = img.getexif()
        except Exception:
            return
        if not exif:
            return

        tags = {TAGS.get(k, k): v for k, v in exif.items()}
        fields = {}
        for key in ("Make", "Model", "DateTime", "Software"):
            if tags.get(key):
                fields[key] = str(tags[key])

        gps_ifd = exif.get_ifd(0x8825) if hasattr(exif, "get_ifd") else {}
        location = self._gps_to_latlon(gps_ifd)
        if location:
            fields["GPS location"] = f"{location[0]:.6f}, {location[1]:.6f}"

        if fields:
            findings.append(
                {
                    "type": "image_exif",
                    "category": "image EXIF exposure" + (" (GPS location)" if location else ""),
                    "detail": f"Image EXIF reveals: {', '.join(f'{k}={v}' for k, v in fields.items())}.",
                    "fields": fields,
                    "source": url,
                }
            )
            sources.append(url)

    @staticmethod
    def _gps_to_latlon(gps_ifd) -> Optional[tuple[float, float]]:
        if not gps_ifd:
            return None
        try:
            from PIL.ExifTags import GPSTAGS

            gps = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            lat, lat_ref = gps.get("GPSLatitude"), gps.get("GPSLatitudeRef")
            lon, lon_ref = gps.get("GPSLongitude"), gps.get("GPSLongitudeRef")
            if not (lat and lon and lat_ref and lon_ref):
                return None

            def to_deg(value) -> float:
                d, m, s = value
                return float(d) + float(m) / 60 + float(s) / 3600

            latitude = to_deg(lat) * (-1 if lat_ref in ("S", "s") else 1)
            longitude = to_deg(lon) * (-1 if lon_ref in ("W", "w") else 1)
            return latitude, longitude
        except Exception:
            return None

    @staticmethod
    def _severity(findings: list[dict]) -> str:
        if any("GPS location" in f["fields"] for f in findings):
            return "HIGH"
        return "MEDIUM" if findings else "CLEAN"
