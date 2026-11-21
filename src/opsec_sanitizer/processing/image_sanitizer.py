"""Pure-pixel image sanitization and irreversible opaque bounding-box redaction."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from PIL import ExifTags, Image, ImageDraw, ImageFilter, ImageOps

from opsec_sanitizer.domain.models import BBox


def _collect_metadata_keys(img: Image.Image) -> tuple[str, ...]:
    keys: list[str] = []
    exif = img.getexif()
    for tag_id in exif:
        tag_name = ExifTags.TAGS.get(tag_id, f"EXIF_{tag_id}")
        keys.append(str(tag_name))
    for info_key in img.info:
        if info_key not in ("jfif", "jfif_version", "jfif_unit", "jfif_density", "dpi"):
            keys.append(str(info_key))
    return tuple(sorted(set(keys)))


def strip_image_to_clean_rgb(
    source_path: Path,
    *,
    paranoid_denoise: bool = False,
) -> tuple[Image.Image, tuple[str, ...]]:
    """Decode an image into a brand-new RGB pixel buffer stripped of all metadata."""
    with Image.open(source_path) as opened:
        removed_keys = _collect_metadata_keys(opened)
        transposed = ImageOps.exif_transpose(opened)
        rgb = transposed.convert("RGB")
        if paranoid_denoise:
            gray = rgb.convert("L").filter(ImageFilter.MedianFilter(size=3))
            rgb = gray.convert("RGB")
        # Rebuild purely from raw pixel bytes so no info/EXIF/ICC survives
        clean = Image.frombytes("RGB", rgb.size, rgb.tobytes())
    return clean, removed_keys


def redact_image_boxes(
    image: Image.Image,
    boxes: Sequence[BBox],
    *,
    padding_px: int = 3,
    fill_color: tuple[int, int, int] = (0, 0, 0),
) -> Image.Image:
    """Return a new image with opaque rectangles painted over all target boxes."""
    clean_copy = Image.frombytes("RGB", image.size, image.convert("RGB").tobytes())
    if not boxes:
        return clean_copy

    draw = ImageDraw.Draw(clean_copy)
    max_w, max_h = float(clean_copy.width), float(clean_copy.height)
    for box in boxes:
        expanded = box.expand(padding=float(padding_px), max_width=max_w, max_height=max_h)
        draw.rectangle(
            (expanded.x0, expanded.y0, expanded.x1, expanded.y1),
            fill=fill_color,
        )
    return clean_copy


def sanitize_image_file(
    source_path: Path,
    output_path: Path,
    *,
    boxes: Sequence[BBox] = (),
    padding_px: int = 3,
    paranoid_denoise: bool = False,
) -> tuple[str, ...]:
    """Strip all metadata, optionally paint redaction boxes, and save a clean PNG."""
    clean_img, removed_keys = strip_image_to_clean_rgb(
        source_path, paranoid_denoise=paranoid_denoise
    )
    redacted_img = redact_image_boxes(clean_img, boxes, padding_px=padding_px)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    redacted_img.save(output_path, format="PNG", optimize=True)
    return removed_keys
