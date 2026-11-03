import pytest

from slugify import slugify


@pytest.mark.parametrize(
    "title,slug",
    [("Hello, World!", "hello-world"), ("  Crème brûlée ", "creme-brulee"), ("---", ""), ("", ""), ("a  b", "a-b")],
)
def test_slugify(title, slug):
    assert slugify(title) == slug


def test_rejects_non_string():
    with pytest.raises(TypeError):
        slugify(None)
