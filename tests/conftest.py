"""Shared test fixtures for Deep View."""
from __future__ import annotations
import pytest
from pathlib import Path
from deepview.core.context import AnalysisContext
from deepview.core.config import DeepViewConfig
from deepview.core.events import EventBus
from deepview.core.logging import setup_logging
from deepview.core.types import Platform

# Ensure structlog is configured for the test session so module-level
# loggers don't write to a closed stderr handle.
setup_logging("warning")

@pytest.fixture
def config():
    """Default test configuration."""
    return DeepViewConfig()

@pytest.fixture
def context():
    """Analysis context for testing."""
    return AnalysisContext.for_testing()

@pytest.fixture
def event_bus():
    """Fresh event bus instance."""
    return EventBus()

@pytest.fixture
def fixtures_dir():
    """Path to test fixtures directory."""
    return Path(__file__).parent / "fixtures"

@pytest.fixture
def memory_samples_dir(fixtures_dir):
    """Path to memory sample fixtures."""
    return fixtures_dir / "memory_samples"

@pytest.fixture
def binaries_dir(fixtures_dir):
    """Path to binary fixtures."""
    return fixtures_dir / "binaries"

@pytest.fixture
def yara_rules_dir(fixtures_dir):
    """Path to YARA rule fixtures."""
    return fixtures_dir / "yara_rules"
