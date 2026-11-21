"""Integration tests for pure pixel image sanitization and opaque redaction."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, PngImagePlugin

from opsec_sanitizer.domain.models import BBox
from opsec_sanitizer.processing.image_sanitizer import (
    redact_image_boxes,
    sanitize_image_file,
    strip_image_to_clean_rgb,
)


def _create_dirty_jpeg(path: Path) -> None:
    img = Image.new("RGB", (120, 80), color=(240, 240, 240))
    exif = Image.Exif()
    exif[271] = "CanonSecretCamera"  # Make
    exif[315] = "InformanteConfidencial"  # Artist
    img.save(path, format="JPEG", exif=exif.tobytes())
    # Append trailing covert bytes after JPEG EOI
    with path.open("ab") as fh:
        fh.write(b"TRAILING_COVERT_PAYLOAD_999")


def _create_dirty_png(path: Path) -> None:
    img = Image.new("RGB", (120, 80), color=(250, 250, 250))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "FuenteSecretaPNG")
    meta.add_text("Comment", "UbicacionGPS_19.4326")
    img.save(path, format="PNG", pnginfo=meta)


class TestImageSanitizer:
    def test_strips_all_exif_and_trailing_bytes_from_jpeg(self, tmp_path: Path) -> None:
        src = tmp_path / "dirty.jpg"
        dst = tmp_path / "clean.png"
        _create_dirty_jpeg(src)

        removed_keys = sanitize_image_file(src, dst)

        raw = dst.read_bytes()
        assert b"CanonSecretCamera" not in raw
        assert b"InformanteConfidencial" not in raw
        assert b"TRAILING_COVERT_PAYLOAD_999" not in raw
        assert len(removed_keys) >= 2
        with Image.open(dst) as clean:
            assert len(clean.getexif()) == 0

    def test_strips_all_text_chunks_from_png(self, tmp_path: Path) -> None:
        src = tmp_path / "dirty.png"
        dst = tmp_path / "clean.png"
        _create_dirty_png(src)

        removed_keys = sanitize_image_file(src, dst)

        raw = dst.read_bytes()
        assert b"FuenteSecretaPNG" not in raw
        assert b"UbicacionGPS_19.4326" not in raw
        assert "Author" in removed_keys
        with Image.open(dst) as clean:
            assert clean.info == {}

    def test_redact_image_boxes_destroys_pixels_opaquely_with_padding(self) -> None:
        base = Image.new("RGB", (100, 100), color=(255, 255, 255))
        box = BBox(x0=20, y0=30, x1=50, y1=45)

        redacted = redact_image_boxes(base, [box], padding_px=4)

        # Original image is NOT mutated (immutability)
        assert base.getpixel((35, 37)) == (255, 255, 255)
        # Inside box and within padding is pure opaque black
        assert redacted.getpixel((35, 37)) == (0, 0, 0)
        assert redacted.getpixel((17, 27)) == (0, 0, 0)
        assert redacted.getpixel((53, 48)) == (0, 0, 0)
        # Outside box + padding stays white
        assert redacted.getpixel((5, 5)) == (255, 255, 255)

    def test_paranoid_denoise_produces_grayscale_clean_rgb(self, tmp_path: Path) -> None:
        src = tmp_path / "color.png"
        # Image with subtle yellow dots (simulating printer MIC tint)
        img = Image.new("RGB", (60, 60), color=(255, 255, 220))
        img.save(src, format="PNG")

        clean, _ = strip_image_to_clean_rgb(src, paranoid_denoise=True)

        # All channels equal (grayscale converted to RGB) and pure yellow tint neutralized
        pixel = clean.getpixel((30, 30))
        assert isinstance(pixel, tuple) and len(pixel) == 3
        r, g, b = pixel
        assert r == g == b
        assert clean.info == {}
