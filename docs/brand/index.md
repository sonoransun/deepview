# Visual Identity

Deep View is a cross-platform forensics and runtime-analysis toolkit. Its visual
identity reflects the product's nature: technical, calm, evidence-oriented, and
most comfortable on a dark terminal window at 03:00. This page is the entry
point to the full brand system.

> "A quiet instrument for loud situations."

## Principles

1. **Dark-mode first.** Every asset ships with Catppuccin Mocha as the base
   palette. Light-mode renderings exist but are secondary; contrast and
   legibility on `#1e1e2e` come first.
2. **Technical, not theatrical.** No neon, no marketing gradients for their own
   sake. Gradients are used sparingly, usually to imply *depth* (layers, lens
   refraction) rather than drama.
3. **Honest about limits.** Deep View is a toolkit, not a silver bullet. The
   brand voice mirrors this — see [Voice and tone](voice-and-tone.md).
4. **Dual-use respectful.** Icons for offensive-capable subsystems (mangle,
   instrumentation) use the same neutral treatment as read-only subsystems.
   The brand never romanticises exploitation.

## Core assets

The three owned asset slots are maintained in `docs/assets/` and are the only
thing third-party integrators should embed directly.

| Asset         | File                                       | Canvas   | Intended use                                                   |
| ------------- | ------------------------------------------ | -------- | -------------------------------------------------------------- |
| Logo          | [`logo.svg`](../assets/logo.svg)           | 256x256  | README header, docs navigation, GitHub social preview fallback |
| Favicon       | [`favicon.svg`](../assets/favicon.svg)     | 32x32    | Browser tab, mkdocs site, CLI install prompts                  |
| Social card   | [`social-card.svg`](../assets/social-card.svg) | 1200x630 | Open Graph / Twitter card / conference slides title page    |

Workflow icons (see [SVG icons](svg-icons.md)) live alongside these files but
are treated as interchangeable UI elements rather than brand marks.

## Download

Right-click → *Save Link As* on any of the following, or clone the repository
and copy from `docs/assets/`.

- Logo (SVG, recommended): [`logo.svg`](../assets/logo.svg)
- Favicon (SVG, recommended): [`favicon.svg`](../assets/favicon.svg)
- Social card (SVG): [`social-card.svg`](../assets/social-card.svg)

Rasterised PNG/ICO variants are deliberately **not** provided — rasterise at
the exact pixel dimensions your integration needs, on a surface matching your
background, so that sub-pixel artefacts stay under your control.

## Usage: do / don't

### Do

- Embed the SVG logo inline in dark HTML contexts; the asset is self-contained
  and does not require external CSS.
- Place the logo on `#1e1e2e` (Catppuccin Mocha *base*) or `#11111b` (*crust*)
  whenever possible. If a light background is unavoidable, keep the existing
  rounded-rectangle background — the logo is designed to be its own surface.
- Use the social card as-is for blog posts, talks, and release announcements.
  Its typography and grid were calibrated for the 1.91:1 Open Graph aspect
  ratio; cropping breaks the data-layer stack on the right.
- Link back to this branding page when embedding Deep View assets in external
  material. The page is versioned with the codebase.

### Don't

- Don't recolour the logo. The mauve-to-teal lens gradient is fixed, and the
  layer stack uses specific surface greys that carry semantic meaning (see
  [Palette](palette.md)).
- Don't add drop shadows, glows, or outer effects. The asset already contains
  a calibrated inner highlight on the lens.
- Don't rotate, shear, or squash. The viewBox is square; non-uniform scaling
  will desaturate the gradient stops.
- Don't combine the logo with another wordmark in a compound lockup without a
  separating rule. The magnifying-glass mark and the "Deep View" wordmark are
  a unit.
- Don't use the logo to endorse third-party products. If you build an
  integration, use the text "Works with Deep View" instead of the mark.

## Related pages

- [Palette](palette.md) — every hex code, surface, and accent.
- [Typography](typography.md) — type stack and sample blocks.
- [Voice and tone](voice-and-tone.md) — how we write docs, errors, release
  notes.
- [SVG icons](svg-icons.md) — the small catalogue of workflow icons.

## Attribution

The palette is [Catppuccin Mocha](https://github.com/catppuccin/catppuccin),
licensed under MIT. Deep View's marks and icons are project-original and
released under the repository's root licence.
