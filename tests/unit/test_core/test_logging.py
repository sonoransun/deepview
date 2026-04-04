"""Tests for structured logging configuration."""
import sys

import structlog

from deepview.core.logging import get_logger, setup_logging


def _reset_logging():
    """Re-configure structlog to a working state after test changes."""
    setup_logging("warning")


class TestSetupLogging:
    def teardown_method(self):
        _reset_logging()

    def test_setup_logging_valid_level(self):
        for level in ("debug", "info", "warning", "error"):
            setup_logging(log_level=level)  # should not raise

    def test_setup_logging_invalid_level(self):
        setup_logging(log_level="bogus")  # should not raise, falls back to INFO


class TestGetLogger:
    def teardown_method(self):
        _reset_logging()

    def test_get_logger_returns_bound_logger(self):
        setup_logging()
        logger = get_logger("test")
        assert hasattr(logger, "info")
        assert hasattr(logger, "debug")
        assert hasattr(logger, "warning")
        assert hasattr(logger, "error")

    def test_get_logger_with_name(self):
        setup_logging()
        logger = get_logger("deepview.core.test")
        assert logger is not None
        assert hasattr(logger, "info")
        assert hasattr(logger, "bind")
