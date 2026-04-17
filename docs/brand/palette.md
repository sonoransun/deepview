# Palette

Deep View uses the [Catppuccin Mocha](https://github.com/catppuccin/catppuccin)
palette as its canonical colour system. Mocha was chosen because it is widely
implemented across editors, terminals, and docs themes, which means
screenshots, terminal casts, and rendered docs all share the same chroma
without manual matching.

The primary accent is **mauve** (`#cba6f7`). Everything else is supporting.

## Base surfaces

These are the flat colours used for backgrounds, cards, modals, and gutters.
They carry a deliberate ordering — deeper values sit behind shallower ones.

| Role      | Hex       | Swatch                                                                        | Notes                                                      |
| --------- | --------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `crust`   | `#11111b` | <span style="background:#11111b; color:#cdd6f4; padding:2px 8px">#11111b</span> | The darkest surface. Used for page gutters and code blocks. |
| `mantle`  | `#181825` | <span style="background:#181825; color:#cdd6f4; padding:2px 8px">#181825</span> | Secondary surface, e.g. sidebar background.                |
| `base`    | `#1e1e2e` | <span style="background:#1e1e2e; color:#cdd6f4; padding:2px 8px">#1e1e2e</span> | The primary page background. Almost everything sits here.  |

## Elevated surfaces

Used for cards, inline chips, hover states, and admonitions. They lift content
*toward* the viewer.

| Role       | Hex       | Swatch                                                                        |
| ---------- | --------- | ----------------------------------------------------------------------------- |
| `surface0` | `#313244` | <span style="background:#313244; color:#cdd6f4; padding:2px 8px">#313244</span> |
| `surface1` | `#45475a` | <span style="background:#45475a; color:#cdd6f4; padding:2px 8px">#45475a</span> |
| `surface2` | `#585b70` | <span style="background:#585b70; color:#cdd6f4; padding:2px 8px">#585b70</span> |

## Text

Body and heading text uses `text` (`#cdd6f4`). Muted metadata uses `subtext1`
(`#bac2de`) or `subtext0` (`#a6adc8`). Placeholder and disabled text uses
`overlay2` (`#9399b2`) down to `overlay0` (`#6c7086`).

| Role       | Hex       | Swatch                                                                        | Use                                          |
| ---------- | --------- | ----------------------------------------------------------------------------- | -------------------------------------------- |
| `text`     | `#cdd6f4` | <span style="background:#1e1e2e; color:#cdd6f4; padding:2px 8px">#cdd6f4</span> | Primary body + headings on `base`.           |
| `subtext1` | `#bac2de` | <span style="background:#1e1e2e; color:#bac2de; padding:2px 8px">#bac2de</span> | Secondary labels, captions.                  |
| `subtext0` | `#a6adc8` | <span style="background:#1e1e2e; color:#a6adc8; padding:2px 8px">#a6adc8</span> | Table metadata, muted timestamps.            |
| `overlay2` | `#9399b2` | <span style="background:#1e1e2e; color:#9399b2; padding:2px 8px">#9399b2</span> | Placeholder text.                            |
| `overlay1` | `#7f849c` | <span style="background:#1e1e2e; color:#7f849c; padding:2px 8px">#7f849c</span> | Grid lines, very faint borders.              |
| `overlay0` | `#6c7086` | <span style="background:#1e1e2e; color:#6c7086; padding:2px 8px">#6c7086</span> | Disabled controls.                           |

## Accents (Deep View roles)

Each accent is mapped to a semantic role. Re-using the same accent for
unrelated concepts makes screenshots and dashboards harder to read, so we
follow this mapping by convention.

| Accent      | Hex       | Swatch                                                                        | Role in Deep View                                                   |
| ----------- | --------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `rosewater` | `#f5e0dc` | <span style="background:#f5e0dc; color:#11111b; padding:2px 8px">#f5e0dc</span> | Hover tint; rare.                                                   |
| `flamingo`  | `#f2cdcd` | <span style="background:#f2cdcd; color:#11111b; padding:2px 8px">#f2cdcd</span> | Decorative only; rare.                                              |
| `pink`      | `#f5c2e7` | <span style="background:#f5c2e7; color:#11111b; padding:2px 8px">#f5c2e7</span> | Instrumentation (Frida, static rewrites).                           |
| `mauve`     | `#cba6f7` | <span style="background:#cba6f7; color:#11111b; padding:2px 8px">#cba6f7</span> | **Primary**. Brand, logo, active links, focus rings.                |
| `red`       | `#f38ba8` | <span style="background:#f38ba8; color:#11111b; padding:2px 8px">#f38ba8</span> | Critical alerts, policy violations, fatal errors.                   |
| `maroon`    | `#eba0ac` | <span style="background:#eba0ac; color:#11111b; padding:2px 8px">#eba0ac</span> | Recoverable errors, expired artefacts.                              |
| `peach`     | `#fab387` | <span style="background:#fab387; color:#11111b; padding:2px 8px">#fab387</span> | Warnings, rate-limit notices, queue-drop indicators.                |
| `yellow`    | `#f9e2af` | <span style="background:#f9e2af; color:#11111b; padding:2px 8px">#f9e2af</span> | Caution labels, experimental plugins, `requires_root` markers.      |
| `green`     | `#a6e3a1` | <span style="background:#a6e3a1; color:#11111b; padding:2px 8px">#a6e3a1</span> | Success, passing checks (`deepview doctor`), confirmed artefacts.   |
| `teal`      | `#94e2d5` | <span style="background:#94e2d5; color:#11111b; padding:2px 8px">#94e2d5</span> | Memory subsystem, DataLayer accents.                                |
| `sky`       | `#89dceb` | <span style="background:#89dceb; color:#11111b; padding:2px 8px">#89dceb</span> | Tracing subsystem, stream indicators.                               |
| `sapphire`  | `#74c7ec` | <span style="background:#74c7ec; color:#11111b; padding:2px 8px">#74c7ec</span> | VM introspection, hypervisor connectors.                            |
| `blue`      | `#89b4fa` | <span style="background:#89b4fa; color:#11111b; padding:2px 8px">#89b4fa</span> | Informational prompts, neutral links.                               |
| `lavender`  | `#b4befe` | <span style="background:#b4befe; color:#11111b; padding:2px 8px">#b4befe</span> | Classification labels, rule metadata.                               |

## Usage examples

### Callout blocks

- **Info** — `blue` left border on `surface0` fill.
- **Success** — `green` left border; body text in `text`.
- **Warning** — `peach` left border; avoid red to keep red reserved for true
  failures.
- **Critical** — `red` left border; body text still in `text`, never on a
  saturated red background.

### Process health badges

The `deepview doctor` output uses:

- `green` **PASS**
- `yellow` **WARN** (optional dep missing, degrading gracefully)
- `red`   **FAIL**
- `overlay0` **SKIP** (platform not applicable)

### Terminal casts

All terminal recordings use Catppuccin Mocha as the terminal theme so that
`pslist` and `netstat` output render at the same chroma as the surrounding
prose. Do not record casts with a light terminal theme.

## Accessibility

Deep View targets **WCAG 2.1 AA** for body copy (minimum contrast ratio
**4.5:1**) and AA Large for chrome (3:1). Key tested pairings:

| Foreground | Background | Contrast ratio | WCAG AA body | Notes                          |
| ---------- | ---------- | -------------- | ------------ | ------------------------------ |
| `#cdd6f4`  | `#1e1e2e`  | 12.5:1         | Pass         | Primary body text.             |
| `#cdd6f4`  | `#11111b`  | 15.4:1         | Pass         | Body on crust.                 |
| `#a6adc8`  | `#1e1e2e`  | 8.3:1          | Pass         | Muted metadata.                |
| `#cba6f7`  | `#1e1e2e`  | 8.1:1          | Pass         | Primary accent link.           |
| `#f38ba8`  | `#1e1e2e`  | 6.7:1          | Pass         | Critical link / error marker.  |
| `#a6e3a1`  | `#1e1e2e`  | 10.3:1         | Pass         | Success badge.                 |
| `#6c7086`  | `#1e1e2e`  | 3.3:1          | Large only   | Only for disabled / decorative. |

Never place body text on a saturated accent. If you must paint a chip with a
mauve fill, use `#11111b` for its label, not `#cdd6f4`.

## Source of truth

If Catppuccin upstream revises a hex value, the upstream wins — but bump
affected figures and screenshots in the same commit so rendered docs stay
consistent.
