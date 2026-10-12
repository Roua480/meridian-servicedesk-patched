# validators.py
#
# validators for file uploads, etc.

from io import BytesIO
from pathlib import Path
import logging
import warnings

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from PIL import Image, UnidentifiedImageError

from helpdesk import settings as helpdesk_settings

# TODO: can we use the builtin Django validator instead?
# see:
# https://docs.djangoproject.com/en/4.0/ref/validators/#fileextensionvalidator


def validate_file_extension(value):
    import os

    from django.core.exceptions import ValidationError
    from django.utils.translation import gettext as _

    if not helpdesk_settings.HELPDESK_VALIDATE_ATTACHMENT_TYPES:
        return

    filename = value.name
    # A committed FieldFile has a storage path, rather than an upload name.
    if getattr(value, "_committed", False):
        filename = Path(filename).name

    if not filename or "/" in filename or "\\" in filename:
        raise ValidationError(_("Invalid filename."), code="filename")

    # Require exactly one dot in the filename.
    if filename.count(".") != 1:
        raise ValidationError(
            _("Multiple or missing extensions are not allowed."),
            code="filename_extensions",
        )

    ext = os.path.splitext(filename)[1].lower()

    if ext not in helpdesk_settings.HELPDESK_VALID_EXTENSIONS:
        raise ValidationError(
            _("Unsupported file extension: ") + ext, code="extension"
        )


def validate_image_content(value):
    
    extension = Path(value.name).suffix.lower()

    if extension not in {".png", ".jpg", ".jpeg"}:
        return

    try:
        value.seek(0)
        image_bytes = value.read()

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            image = Image.open(BytesIO(image_bytes))
        with image:
            value.detected_type = Image.MIME.get(image.format, "unknown")
            # Reject images with more than 20 million pixels
            max_pixels = 20_000_000

            width, height = image.size

            if width * height > max_pixels:
                raise ValidationError(
                    _("Image dimensions exceed the allowed limit."),
                    code="image_dimensions",
                )
            expected_format = (
                "PNG" if extension == ".png" else "JPEG"
            )

            if image.format != expected_format:
                raise ValidationError(
                    _("Image contents do not match the extension."),
                    code="image_format",
                )

            image.verify()
        # verify() does not decode pixels (and is a no-op for JPEG).
        with Image.open(BytesIO(image_bytes)) as image:
            image.load()

    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ValidationError(
            _("Image dimensions exceed the allowed limit."), code="image_dimensions"
        ) from None
    except (
        UnidentifiedImageError, OSError, ValueError, SyntaxError, EOFError, MemoryError
    ):
        raise ValidationError(
            _("Invalid or corrupted image file."), code="image_decode"
        ) from None
    finally:
        value.seek(0)


def validate_attachment_size(value):
    from django.core.exceptions import ValidationError

    max_size = 10 * 1024 * 1024  # 10 MiB

    if value.size > max_size:
        raise ValidationError(
            "Attachment exceeds the 10 MB size limit.", code="attachment_size"
        )


def log_attachment_decision(value, owner_id, errors=None, stored_name=None):
    """Log only server-controlled metadata; rejected files have no stored name."""
    detected_type = getattr(value, "detected_type", None)
    if detected_type is None:
        detected_type = getattr(
            getattr(value, "file", None), "detected_type", "unknown"
        )
    logging.getLogger("helpdesk").log(
        logging.WARNING if errors else logging.INFO,
        "Attachment %s: stored_name=%s, owner=%s, size=%s, detected_type=%s, check=%s",
        "rejected" if errors else "accepted",
        Path(stored_name).name if stored_name else "not_stored",
        owner_id if owner_id is not None else "anonymous",
        getattr(value, "size", "unknown"),
        detected_type,
        ",".join(sorted({error.code or "validation" for error in errors}))
        if errors else "passed",
    )
