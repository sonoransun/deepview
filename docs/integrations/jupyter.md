# Jupyter Notebooks

Deep View is usable as a library inside any Jupyter kernel — which is
the most natural environment for exploratory forensics. The
`AnalysisContext` is decoupled from the CLI, so you can instantiate it
directly, feed it a memory image or a live process, and render
`PluginResult.rows` as pandas DataFrames for interactive analysis.

This guide walks through a notebook template that:

1. Creates an `AnalysisContext` (test flavor and production flavor).
2. Runs a built-in plugin (`pslist`, `filesystem_timeline`,
   `netscan`).
3. Loads the `PluginResult` into a pandas DataFrame.
4. Plots a matplotlib timeline of events.
5. Replays a session store via `replay/SessionReplayer`.

See [reference/plugins][plugins] for the underlying types.

[plugins]: ../reference/plugins.md

## Setup

```bash
pip install -e ".[dev,memory,tracing]"
pip install jupyterlab pandas matplotlib seaborn
jupyter lab
```

Inside the notebook:

```python
%load_ext autoreload
%autoreload 2

from deepview.core.context import AnalysisContext
ctx = AnalysisContext.for_testing()
ctx.platform
```

`for_testing()` constructs a context with stub layers, an in-memory
event bus, and a synthetic platform record — ideal for notebook demos
that do not need real root access. For real analysis, call
`AnalysisContext.create()` and attach a memory layer explicitly.

## Running a plugin

```python
from deepview.plugins.builtin.pslist import PsListPlugin

plugin = PsListPlugin(ctx)
result = plugin.run()
print(result.success, result.columns)
```

`PluginResult.rows` is a list of tuples in column order — perfect for
pandas:

```python
import pandas as pd
df = pd.DataFrame(result.rows, columns=result.columns)
df.head()
```

=== "DataFrame preview"

    ```text
         pid  ppid   name       start_time        state
    0      1     0   systemd    2026-04-14 08:00  S
    1   4711  4500   bash       2026-04-14 09:12  S
    2   4712  4711   curl       2026-04-14 09:12  R
    ```

=== "Group by parent"

    ```python
    df.groupby("ppid").size().sort_values(ascending=False).head(10)
    ```

## Filesystem timeline

The `filesystem_timeline` plugin ingests an `$MFT` or ext4 inode table
and emits MACB rows:

```python
from deepview.plugins.builtin.filesystem_timeline import FilesystemTimelinePlugin
plugin = FilesystemTimelinePlugin(ctx, volume="/evidence/disk.raw")
tl = plugin.run()
tl_df = pd.DataFrame(tl.rows, columns=tl.columns)
tl_df["timestamp"] = pd.to_datetime(tl_df["timestamp"])
tl_df.set_index("timestamp", inplace=True)
```

### Plotting

```python
import matplotlib.pyplot as plt

fig, ax = plt.subplots(figsize=(12, 4))
tl_df.resample("1min")["path"].count().plot(ax=ax)
ax.set_title("Filesystem events / minute")
ax.set_ylabel("count")
plt.tight_layout()
```

A stacked view by MACB type:

```python
(
    tl_df.groupby([pd.Grouper(freq="1min"), "macb"])
         .size()
         .unstack(fill_value=0)
         .plot.area(stacked=True, figsize=(12, 4), alpha=0.7)
)
```

## Event bus introspection

Subscribe to typed events inside the notebook and buffer them into a
DataFrame:

```python
from collections import deque
from deepview.core.events import EventClassifiedEvent

buf: deque = deque(maxlen=5000)
ctx.events.subscribe(EventClassifiedEvent, lambda e: buf.append(e))
```

Run a live `TraceManager` in a background thread:

```python
import asyncio, threading
from deepview.tracing.manager import TraceManager

def start():
    tm = TraceManager.from_context(ctx)
    asyncio.new_event_loop().run_until_complete(tm.run_forever())

threading.Thread(target=start, daemon=True).start()
```

After a few seconds, pull the buffer into pandas:

```python
import dataclasses
evt_df = pd.DataFrame([dataclasses.asdict(e) for e in buf])
evt_df["timestamp"] = pd.to_datetime(evt_df["timestamp"])
evt_df.groupby("rule_name").size().sort_values(ascending=False).head()
```

## Replaying a session store

`replay/SessionStore` persists events to SQLite. You can open one
read-only in a notebook:

```python
from deepview.replay import SessionReader

reader = SessionReader("/var/deepview/sessions/2026-04-13.sqlite")
rows = list(reader.iter_events(kind="event_classified"))
rep_df = pd.DataFrame(rows)
rep_df.head()
```

Drive a `SessionReplayer` at 10x speed to re-animate a detection:

```python
from deepview.replay import SessionReplayer

replayer = SessionReplayer(reader, speed=10.0)
async def go():
    async for e in replayer.play():
        if hasattr(e, "rule_name"):
            print(e.timestamp, e.rule_name, e.process)

await go()
```

!!! tip "Interactive analysis pattern"
    Keep the notebook's kernel long-lived and use cell-by-cell buffers
    so you don't lose state when a plugin raises. Wrap each plugin run
    in a `try/except` and pickle `PluginResult.rows` to disk if you
    need durable artifacts.

## Widgets

For a responsive UI, combine `ipywidgets` with the DataFrame:

```python
import ipywidgets as widgets

severity = widgets.Dropdown(options=["low", "medium", "high", "critical"])

def render(change):
    subset = evt_df[evt_df["severity"] == severity.value]
    display(subset.head(50))

severity.observe(render, names="value")
display(severity)
```

!!! warning "Caveats"
    - **Threading model.** `TraceManager.run_forever()` wants its own
      event loop. Running it in the notebook kernel's loop blocks all
      other cells — always spin a background thread.
    - **DataFrame memory.** Filesystem timelines can reach tens of
      millions of rows; use `pd.read_parquet()` / `dask.dataframe` for
      anything larger than ~1M rows.
    - **Autoreload edge cases.** `%autoreload 2` does not re-decorate
      plugins. After editing a plugin, restart the kernel or re-import
      the plugin module explicitly.
    - **Schema drift.** `PluginResult.columns` can change between Deep
      View versions; do not rely on positional indexing across
      upgrades.
    - **Live data + notebooks.** If the kernel crashes mid-capture the
      in-memory buffer is lost. Mirror critical events to a
      `SessionStore` for durability.
