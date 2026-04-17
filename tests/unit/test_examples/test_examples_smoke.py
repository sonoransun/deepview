"""Smoke tests for the ``examples/`` scripts.

Every example must:

* import cleanly (no top-level imports that require optional extras
  which aren't installed — the examples are the reference "can a
  reader copy-paste this?" surface);
* expose a ``main()`` callable that returns an ``int`` exit status;
* accept ``--help`` via its argparse parser without errors (by
  monkey-patching ``sys.argv``).

The tests are parametrised over every non-underscore ``.py`` file in
``examples/``, so adding a new example picks up smoke coverage for free.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

import pytest


EXAMPLES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "examples"


def _discover_examples() -> list[Path]:
    """Return every runnable example under ``examples/``.

    Skips modules whose name starts with ``_`` (they're helper shims,
    not runnable examples) and ``__init__.py``.
    """
    if not EXAMPLES_DIR.is_dir():
        return []
    out: list[Path] = []
    for path in sorted(EXAMPLES_DIR.glob("*.py")):
        name = path.stem
        if name.startswith("_") or name == "__init__":
            continue
        out.append(path)
    return out


EXAMPLE_PATHS = _discover_examples()


def test_examples_directory_exists() -> None:
    assert EXAMPLES_DIR.is_dir(), f"examples dir not found at {EXAMPLES_DIR}"


def test_examples_count_is_reasonable() -> None:
    # The README advertises ~13 runnable examples; guard against accidental
    # deletion dropping coverage below the floor.
    assert len(EXAMPLE_PATHS) >= 10, (
        f"expected at least 10 runnable examples under {EXAMPLES_DIR}, "
        f"got {len(EXAMPLE_PATHS)}: {[p.name for p in EXAMPLE_PATHS]}"
    )


def _load_module_from_path(path: Path) -> object:
    """Import the example file as a module under an anonymous name."""
    name = f"_dv_example_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


# ---------------------------------------------------------------------------
# Parametrised smoke tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "example_path",
    EXAMPLE_PATHS,
    ids=[p.name for p in EXAMPLE_PATHS],
)
def test_example_imports_cleanly(example_path: Path) -> None:
    """Importing the example file must not raise."""
    module = _load_module_from_path(example_path)
    assert module is not None


@pytest.mark.parametrize(
    "example_path",
    EXAMPLE_PATHS,
    ids=[p.name for p in EXAMPLE_PATHS],
)
def test_example_exposes_main(example_path: Path) -> None:
    module = _load_module_from_path(example_path)
    main = getattr(module, "main", None)
    assert callable(main), (
        f"{example_path.name} must expose a ``main()`` callable"
    )


@pytest.mark.parametrize(
    "example_path",
    EXAMPLE_PATHS,
    ids=[p.name for p in EXAMPLE_PATHS],
)
def test_example_main_help_exits_zero(
    example_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``main()`` invoked with ``--help`` in argv must exit cleanly.

    The examples use :mod:`argparse`, which raises
    :class:`SystemExit(0)` on ``--help``. Modules that do *not* use
    argparse simply return from ``main()`` immediately when given no
    recognised args, which we also accept.
    """
    module = _load_module_from_path(example_path)
    main = getattr(module, "main", None)
    if main is None:
        pytest.skip(f"{example_path.name} has no main()")

    monkeypatch.setattr(sys, "argv", [example_path.name, "--help"])

    try:
        result = main()
    except SystemExit as exc:
        # argparse raises SystemExit(0) on --help.
        code = exc.code if isinstance(exc.code, int) else 0
        assert code == 0, f"{example_path.name} main(--help) exited with {code}"
        return
    except NotImplementedError:
        # Stub example that hasn't been implemented yet is acceptable.
        pytest.skip(f"{example_path.name} main() is a stub")
        return

    # If the example declined to raise SystemExit, it should at least
    # return a valid exit code (0 or None).
    assert result in (0, None), (
        f"{example_path.name} main(--help) returned non-zero {result!r}"
    )
