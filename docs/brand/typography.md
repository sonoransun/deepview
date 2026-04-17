# Typography

Deep View's type system is deliberately short: one variable sans for UI and
prose, one monospace for code, command output, and terminal renderings.

## Type stack

### UI and prose — Inter

```css
font-family: "Inter", "Inter var", -apple-system, BlinkMacSystemFont,
             "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
font-feature-settings: "ss01", "ss02", "cv11"; /* disambiguated 1/l/I */
```

Inter is preferred because:

- The variable axis makes it possible to use a single font file across
  weights 100-900 without shipping multiple static TTFs.
- The stylistic sets (`ss01`, `ss02`, `cv11`) make `1`, `l`, and `I`
  visually distinct, which matters when the docs are literally full of
  hex dumps and PIDs.
- It renders well on sub-pixel LCD panels down to 12px.

When Inter is unavailable the fallback chain lands on the host OS's system UI
font, which keeps the docs readable on first paint even before web fonts load.

### Code and terminal — JetBrains Mono

```css
font-family: "JetBrains Mono", "Fira Code", "SF Mono", Menlo, Consolas,
             "Liberation Mono", monospace;
font-feature-settings: "calt" off; /* disable programming ligatures in docs */
```

JetBrains Mono was chosen for its height-to-width ratio (denser than
`Menlo`, easier to align columns in `pslist` output) and for its
disambiguated zero (`0` vs `O`). Ligatures are **disabled** in the doc
site because operators need to copy exact byte sequences; `!=` rendered as a
single glyph is a paper cut we do not want.

## Scale

A conservative modular scale, base 16px, ratio 1.2 (minor third). Line-height
follows a 4px baseline grid.

| Token  | rem     | px   | Usage                                                         |
| ------ | ------- | ---- | ------------------------------------------------------------- |
| `xs`   | 0.75    | 12   | Fine print, tooltip bodies, keyboard-shortcut chips.          |
| `sm`   | 0.875   | 14   | Captions, table cells, CLI flag descriptions.                 |
| `md`   | 1.000   | 16   | Primary body copy.                                            |
| `lg`   | 1.125   | 18   | Lead paragraphs on landing pages.                             |
| `xl`   | 1.333   | ~21  | H3.                                                           |
| `2xl`  | 1.602   | ~26  | H2.                                                           |
| `3xl`  | 1.953   | ~31  | H1 on interior pages.                                         |
| `4xl`  | 2.441   | ~39  | Hero / cover heading on the landing page.                     |

## Samples

### H1 — page title

> # Memory acquisition — the boring details matter

### H2 — section

> ## Choosing between LiME, AVML, and winpmem

### H3 — subsection

> ### Kernel module loading on locked-down hosts

### Body

> The `AnalysisContext` owns every subsystem handle for the life of a
> session. Treat it as a dependency-injection container: subsystems acquire
> references from it rather than constructing siblings directly.

### Caption

> *Figure 3.* The pre-check sits in the poll thread, evaluating cheap
> predicates before handing the full event off to the bus.

### Code block

```python
from deepview.core.context import AnalysisContext
from deepview.memory.manager import MemoryManager

ctx = AnalysisContext.for_testing()
manager = MemoryManager.from_context(ctx)
layer = manager.load("evidence/dump.lime")
```

### Inline code

The CLI entry point is `deepview.cli.app:main`; `python -m deepview` routes
through `src/deepview/__main__.py` to the same function.

### Keyboard shortcut

Press **Ctrl+R** then type `monitor` to resume the live trace.

## Weights

We use at most three weights per page to keep the site lightweight.

- **400 (regular)** — body.
- **500 (medium)** — UI controls, table headers.
- **700 (bold)** — headings, very selective emphasis.

Italics are reserved for:

- Citations and figure captions.
- Variables in prose (e.g. *pid*, *tid*).
- Work-in-progress notes.

Never use italics for emphasis when bold would do — italic Inter is a
slightly weaker visual than bold and it disappears on low-contrast screens.

## Offline / air-gapped rendering

Deep View is deployed into air-gapped forensics labs more often than it
isn't. The mkdocs build therefore self-hosts both fonts under
`docs/stylesheets/fonts/` (owned by the docs-theme slice). If those files
are missing for any reason, the CSS fallback chain kicks in and the site
stays readable — you'll lose Inter's stylistic sets but nothing else.

## Do / don't

- **Do** keep line length between 60 and 80 characters in prose.
- **Do** use JetBrains Mono for literal command output, even inside a
  paragraph (use inline code formatting).
- **Don't** bold entire paragraphs for emphasis.
- **Don't** mix Inter with another sans on the same page.
- **Don't** enable programming ligatures in rendered docs — they break
  copy-paste of operator-facing commands.
