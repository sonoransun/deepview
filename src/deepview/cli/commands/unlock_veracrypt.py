"""Historical standalone VeraCrypt / TrueCrypt CLI group (deprecated).

When slice 16 was written, slice 15's ``unlock.py`` was not guaranteed
to exist yet. The fork plan allowed slice 16 to ship a standalone
``unlock-vc`` group that the orchestrator would later merge into the
shared ``unlock`` group. The merged subcommands now live in
:mod:`deepview.cli.commands.unlock`; this module is retained only so
any callers that imported ``unlock_vc`` during the in-flight period
still resolve and find a thin re-export.

No new code should import from here — prefer
``deepview.cli.commands.unlock.unlock`` directly.
"""
from __future__ import annotations

from deepview.cli.commands.unlock import unlock as unlock_vc

__all__ = ["unlock_vc"]
