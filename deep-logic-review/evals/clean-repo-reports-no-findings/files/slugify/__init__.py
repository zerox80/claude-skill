import re
import unicodedata


def slugify(title):
    """Return a URL slug for `title`, or "" when nothing usable remains."""
    if not isinstance(title, str):
        raise TypeError("title must be a string")
    ascii_title = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", "-", ascii_title.lower()).strip("-")
