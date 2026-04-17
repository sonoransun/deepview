# 0003. MkDocs-Material over Sphinx for documentation

- **Status:** Accepted
- **Date:** 2026-04-15

## Context

Deep View's v0.2 release added ~25k LOC of new subsystems — storage,
offload, container unlock, remote acquisition — but the user-facing
documentation had not kept up. The existing `README.md` had a single
mermaid diagram that predated the new work; there was no `docs/` tree,
no static site, no animated assets.

The project needs a documentation build system. The two natural options
are Sphinx (the Python-ecosystem default, with autodoc) and MkDocs-Material
(markdown-first, modern, thriving theme ecosystem).

The decision shapes how narrative docs, reference material, diagrams,
and asciinema casts integrate.

## Decision

**We use MkDocs-Material as the site generator**, configured with:

- `mkdocs-mermaid2-plugin` for native mermaid rendering of sequence,
  class, state, graph, and journey diagrams.
- `pymdownx.superfences` and `pymdownx.tabbed` for rich code blocks and
  tabbed alternatives (e.g., bash vs. zsh, platform variants).
- `mkdocs-asciinema-player-plugin` for embedded terminal recordings.
- Admonitions, code-annotations, and the Material theme's social /
  search features.

Reference pages **link to source files** rather than auto-generating
API tables from docstrings. Internal docstrings remain the canonical
source of truth; reference pages quote them with `pymdownx.snippets`
when we want the code's narrative to appear verbatim.

The docs extra is opt-in (`pip install -e ".[docs]"`) and is *not*
pulled into the `dev` extra — contributors working on docs declare it
explicitly.

## Consequences

### Positive

- **Markdown-first authorship** matches the existing convention
  (`README.md`, `CLAUDE.md`, `CHANGELOG.md`). Contributors don't need
  to learn reStructuredText.
- **Mermaid works natively** both on GitHub (which renders mermaid
  fenced blocks since 2022) and in the rendered site, so a single
  source renders in both locations.
- **Material theme** ships with navigation, search, dark mode, social
  cards, and code annotations out of the box; no theme authoring
  needed.
- **Zero source coupling.** The docs tree can be renamed, restructured,
  or rewritten without any source file needing to move.
- **Fast build.** `mkdocs build --strict` runs in seconds on a laptop;
  no LaTeX, no Sphinx-autodoc import walk.
- **CI simplicity.** A single `mkdocs build --strict` job in GitHub
  Actions catches broken links, missing nav entries, and mermaid
  parse errors.

### Negative

- **No auto-generated API reference.** We trade autodoc for manual
  reference pages. For a project whose public API is still stabilising,
  we think narrative > exhaustive signature tables — but if a user
  wants the precise signature of a class, they must open the source
  file.
- **Reference pages can drift from code.** We mitigate with
  `pymdownx.snippets` for code inclusion and with the ADR rule that
  reference pages link to source.
- **Cross-reference sugar is weaker.** Sphinx's `:py:class:` role
  resolves symbols across the project; MkDocs uses plain markdown
  links that break silently if a target disappears. `--strict` mode
  catches intra-doc link breaks but not code-symbol breaks.

### Neutral

- If we ever need autodoc-style API reference, `mkdocstrings` is a
  well-maintained MkDocs plugin that reads docstrings and renders them
  as markdown. We can add it incrementally without changing the build
  toolchain.
- The Material theme's licence is MIT; Insiders features are not used.

## Alternatives considered

### Option A — Sphinx + autodoc + MyST parser

MyST lets Sphinx consume markdown, which partially addresses the
rST-aversion argument. Rejected because:

- The autodoc-walking-code-at-build-time coupling is exactly what we
  want to avoid (it forces every doc build to succeed at importing
  every module, which fights ADR 0002's lazy-import rule).
- Mermaid needs `sphinxcontrib-mermaid` and still doesn't render on
  plain GitHub without duplication.
- Asciinema embedding requires a custom directive.
- The Furo / pydata-sphinx-theme ecosystem is good but not as
  cohesive as Material.

### Option B — pdoc

Generates a reference site from docstrings. Good for pure API docs,
but Deep View's docs are 70% narrative (architecture, guides, ADRs),
where pdoc has nothing to offer. Rejected.

### Option C — Hand-written HTML + no generator

Rejected as a regression — loses navigation, search, and link
checking.

### Option D — Read the Docs hosted Sphinx

Shares all of Sphinx's downsides plus a hosting dependency; we prefer
GitHub Pages for zero-friction ownership.

## References

- Canonical plan: `/root/.claude/plans/serene-sleeping-starlight.md`
  (the documentation overhaul plan).
- MkDocs-Material: https://squidfunk.github.io/mkdocs-material/
- Plugin: https://github.com/fralau/mkdocs-mermaid2-plugin
- Plugin: https://github.com/BWStearns/mkdocs-asciinema-player-plugin
- Related ADR: [0002 — Lazy-import optional deps](0002-lazy-import-optional-deps.md)
  (the coupling we avoid by rejecting autodoc).
- Architecture page: [`../overview/architecture.md`](../overview/architecture.md)
