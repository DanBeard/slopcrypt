"""
Pytest configuration for cross-compatibility tests.
"""

import json
from pathlib import Path

import pytest

# Path to fixtures directory
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def pytest_addoption(parser):
    """Add custom command-line options."""
    parser.addoption(
        "--ts-fixtures",
        action="store_true",
        default=False,
        help="Run tests with TypeScript-generated fixtures",
    )


@pytest.fixture
def fixtures_dir() -> Path:
    """Return path to fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def use_ts_fixtures(request) -> bool:
    """Return True if testing with TypeScript-generated fixtures."""
    return request.config.getoption("--ts-fixtures")


@pytest.fixture
def crypto_vectors(fixtures_dir: Path) -> dict:
    """Load crypto test vectors from fixtures."""
    path = fixtures_dir / "crypto_vectors.json"
    if not path.exists():
        pytest.skip(f"Fixture file not found: {path}")
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def secret_blobs(fixtures_dir: Path) -> dict:
    """Load secret blob test data from fixtures."""
    path = fixtures_dir / "secret_blobs.json"
    if not path.exists():
        pytest.skip(f"Fixture file not found: {path}")
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def huffman_data(fixtures_dir: Path) -> dict:
    """Load Huffman test data from fixtures."""
    path = fixtures_dir / "huffman_data.json"
    if not path.exists():
        pytest.skip(f"Fixture file not found: {path}")
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def stego_roundtrip(fixtures_dir: Path) -> dict:
    """Load full stego roundtrip test data from fixtures."""
    path = fixtures_dir / "stego_roundtrip.json"
    if not path.exists():
        pytest.skip(f"Fixture file not found: {path}")
    with open(path) as f:
        return json.load(f)
