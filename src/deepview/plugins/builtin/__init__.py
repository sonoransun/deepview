"""Built-in Deep View plugins. Import triggers @register_plugin decorators."""
from deepview.plugins.builtin import pslist
from deepview.plugins.builtin import netstat
from deepview.plugins.builtin import malfind
from deepview.plugins.builtin import timeliner
from deepview.plugins.builtin import dkom_detect
from deepview.plugins.builtin import credentials
from deepview.plugins.builtin import pagetable_walk
from deepview.plugins.builtin import strings
from deepview.plugins.builtin import command_history
from deepview.plugins.builtin import linux_proc
from deepview.plugins.builtin import linux_netstat
from deepview.plugins.builtin import linux_ns
from deepview.plugins.builtin import linux_modules
from deepview.plugins.builtin import linux_kernel_taint

try:
    from deepview.plugins.builtin import remote_image_status  # noqa: F401
except Exception:  # noqa: BLE001
    # Remote acquisition subsystem may not be importable during partial
    # installs. The plugin itself is stdlib-only and should normally
    # register, but we guard to keep plugin discovery robust.
    pass

# Storage / filesystem / NAND plugins — each wrapped so a missing optional
# dep in any one of them never aborts plugin discovery as a whole.
try:
    from deepview.plugins.builtin import filesystem_ls  # noqa: F401
except Exception:  # noqa: BLE001  # pragma: no cover - optional-dep path
    pass
try:
    from deepview.plugins.builtin import filesystem_timeline  # noqa: F401
except Exception:  # noqa: BLE001  # pragma: no cover - optional-dep path
    pass
try:
    from deepview.plugins.builtin import nand_decode  # noqa: F401
except Exception:  # noqa: BLE001  # pragma: no cover - optional-dep path
    pass
try:
    from deepview.plugins.builtin import swap_extract  # noqa: F401
except Exception:  # noqa: BLE001  # pragma: no cover - optional-dep path
    pass
try:
    from deepview.plugins.builtin import deleted_file_carve  # noqa: F401
except Exception:  # noqa: BLE001  # pragma: no cover - optional-dep path
    pass
try:
    from deepview.plugins.builtin import volume_unlock  # noqa: F401
except Exception:  # noqa: BLE001  # pragma: no cover - optional-dep path
    pass
try:
    from deepview.plugins.builtin import extracted_keys  # noqa: F401
except Exception:  # noqa: BLE001  # pragma: no cover - optional-dep path
    pass
