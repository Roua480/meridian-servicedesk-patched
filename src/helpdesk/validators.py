# validators.py
#
# validators for file uploads, etc.

from io import BytesIO
from pathlib import Path

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

    if not filename or "/" in filename or "\\" in filename:
        raise ValidationError(_("Invalid filename."))

    # Require exactly one dot in the filename.
    if filename.count(".") != 1:
        raise ValidationError(_("Multiple or missing extensions are not allowed."))

    ext = os.path.splitext(filename)[1].lower()

    if ext not in helpdesk_settings.HELPDESK_VALID_EXTENSIONS:
        raise ValidationError(_("Unsupported file extension: ") + ext)


def validate_image_content(value):
    
    extension = Path(value.name).suffix.lower()

    if extension not in {".png", ".jpg", ".jpeg"}:
        return

    try:
        value.seek(0)
        image_bytes = value.read()

        with Image.open(BytesIO(image_bytes)) as image:
            # Reject images with more than 20 million pixels
            max_pixels = 20_000_000

            width, height = image.size

            if width * height > max_pixels:
                raise ValidationError(
                    _("Image dimensions exceed the allowed limit.")
                )
            expected_format = (
                "PNG" if extension == ".png" else "JPEG"
            )

            if image.format != expected_format:
                raise ValidationError(
                    _("Image contents do not match the extension.")
                )

            image.verify()

    except (UnidentifiedImageError, OSError, ValueError):
        raise ValidationError(
            _("Invalid or corrupted image file.")
        )
    finally:
        value.seek(0)


def validate_attachment_size(value):
    from django.core.exceptions import ValidationError

    max_size = 10 * 1024 * 1024  # 10 MiB

    if value.size > max_size:
        raise ValidationError(
            "Attachment exceeds the 10 MB size limit."
        )