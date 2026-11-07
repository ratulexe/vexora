import pytest

from app.cache import clear_all
from app.rate_limit import clear_all as clear_rate_limits


@pytest.fixture(autouse=True)
def empty_caches():
    """Every test starts with empty caches, so results never leak between tests."""
    clear_all()
    clear_rate_limits()
    yield
    clear_all()
    clear_rate_limits()
