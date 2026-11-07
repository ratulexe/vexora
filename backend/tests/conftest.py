import pytest

from app.cache import clear_all


@pytest.fixture(autouse=True)
def empty_caches():
    """Every test starts with empty caches, so results never leak between tests."""
    clear_all()
    yield
    clear_all()
