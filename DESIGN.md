---
name: "agents-doctor"
description: "The visual system of the agents-doctor explorer: a native macOS utility window, light and dark, built from inset grouped surfaces and state colour."
colors:
  # The appearance follows the system. A token with a value for each appearance
  # appears twice, as "<name>-light" and "<name>-dark". The names are the custom
  # properties of skills/agents-doctor/scripts/ui/static/style.css, without "--".
  # Surfaces
  window-light: "#f5f5f7"
  window-dark: "#1e1e20"
  surface-light: "#ffffff"
  surface-dark: "#2c2c2e"
  surface-alt-light: "#ebebed"
  surface-alt-dark: "#29292b"
  surface-hover-light: "#f0f0f2"
  surface-hover-dark: "#38383a"
  surface-active-light: "#e0e0e3"
  surface-active-dark: "#424446"
  surface-selected-light: "#e2ecff"
  surface-selected-dark: "#1d3a5c"
  backdrop-light: "rgba(0, 0, 0, 0.25)"
  backdrop-dark: "rgba(0, 0, 0, 0.5)"
  # Lines
  separator-light: "rgba(0, 0, 0, 0.08)"
  separator-dark: "rgba(255, 255, 255, 0.10)"
  border-light: "rgba(0, 0, 0, 0.10)"
  border-dark: "rgba(255, 255, 255, 0.12)"
  border-strong-light: "rgba(0, 0, 0, 0.16)"
  border-strong-dark: "rgba(255, 255, 255, 0.18)"
  # Text
  text-light: "#1d1d1f"
  text-dark: "#f5f5f7"
  text-muted-light: "#66666b"
  text-muted-dark: "#a6a6ab"
  text-faint-light: "#86868b"
  text-faint-dark: "#8e8e93"
  text-secondary-strong-light: "#515154"
  text-secondary-strong-dark: "#c7c7cc"
  placeholder-light: "#66666b"
  placeholder-dark: "#a6a6ab"
  on-accent: "#ffffff"
  # Primary is the accent family: --accent, --accent-text, --accent-fill,
  # --accent-fill-hover, --accent-dim
  primary-light: "#007aff"
  primary-dark: "#0a84ff"
  primary-text-light: "#0040dd"
  primary-text-dark: "#5aa8ff"
  primary-fill-light: "#0066d6"
  primary-fill-dark: "#0071e6"
  primary-fill-hover-light: "#0071ee"
  primary-fill-hover-dark: "#0a74e0"
  primary-dim-light: "rgba(0, 122, 255, 0.14)"
  primary-dim-dark: "rgba(10, 132, 255, 0.16)"
  # State palette: a fill and a text twin for each colour
  red-light: "#ff3b30"
  red-dark: "#ff453a"
  red-text-light: "#cd0015"
  red-text-dark: "#ff8279"
  orange-light: "#ff9500"
  orange-dark: "#ff9f0a"
  orange-text-light: "#c03200"
  orange-text-dark: "#ffb340"
  yellow-light: "#ffcc00"
  yellow-dark: "#ffd60a"
  yellow-text-light: "#8c5800"
  yellow-text-dark: "#ffd60a"
  green-light: "#34c759"
  green-dark: "#30d158"
  green-text-light: "#19702f"
  green-text-dark: "#30d158"
  blue-light: "#007aff"
  blue-dark: "#0a84ff"
  blue-text-light: "#0040dd"
  blue-text-dark: "#5aa8ff"
  purple-text-light: "#8944ab"
  purple-text-dark: "#da8fff"
  gray-light: "#8e8e93"
  gray-dark: "#98989d"
  gray-text-light: "#66666b"
  gray-text-dark: "#a6a6ab"
  # TreeMap scale
  tm-top-light: "#e4e4e9"
  tm-top-dark: "#3a3a3e"
  tm-hot-light: "#93c5ff"
  tm-hot-dark: "#1b66c0"
  tm-hatch-light: "rgba(0, 0, 0, 0.07)"
  tm-hatch-dark: "rgba(255, 255, 255, 0.10)"
  # Browser surfaces
  selection-light: "rgba(0, 122, 255, 0.20)"
  selection-dark: "rgba(10, 132, 255, 0.40)"
  scrollbar-thumb-light: "rgba(0, 0, 0, 0.26)"
  scrollbar-thumb-dark: "rgba(255, 255, 255, 0.28)"
typography:
  display:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif'
    fontSize: "28px"
    fontWeight: 600
    lineHeight: 1.1
    letterSpacing: "-0.015em"
  headline:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif'
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.35
  title:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif'
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.45
  body:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif'
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.45
  body-small:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif'
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: '-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif'
    fontSize: "11px"
    fontWeight: 500
  mono:
    fontFamily: 'ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Cascadia Mono", "Liberation Mono", monospace'
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "18px"
rounded:
  # --radius-control and --radius-surface are tokens; the two below are
  # recurring values of the stylesheet that have no token of their own
  control: "6px"
  surface: "10px"
  sheet: "12px"
  capsule: "999px"
spacing:
  # The stylesheet sets spacing in literal pixels; these are the steps that recur
  4: "4px"
  6: "6px"
  8: "8px"
  10: "10px"
  12: "12px"
  16: "16px"
  20: "20px"
components:
  # Each component is given for the light appearance and again, with the suffix
  # "-dark", for the dark one. Hover, press and focus are described under Components.
  button-push:
    backgroundColor: "{colors.surface-light}"
    textColor: "{colors.text-light}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "26px"
  button-push-hover:
    backgroundColor: "{colors.surface-hover-light}"
  button-push-dark:
    backgroundColor: "{colors.surface-dark}"
    textColor: "{colors.text-dark}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "26px"
  button-push-dark-hover:
    backgroundColor: "{colors.surface-hover-dark}"
  button-prominent:
    backgroundColor: "{colors.primary-fill-light}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "26px"
  button-prominent-hover:
    backgroundColor: "{colors.primary-fill-hover-light}"
  button-prominent-dark:
    backgroundColor: "{colors.primary-fill-dark}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "26px"
  button-prominent-dark-hover:
    backgroundColor: "{colors.primary-fill-hover-dark}"
  button-icon:
    backgroundColor: "transparent"
    textColor: "{colors.text-light}"
    rounded: "{rounded.control}"
    padding: "0 6px"
    width: "28px"
    height: "28px"
  button-icon-dark:
    backgroundColor: "transparent"
    textColor: "{colors.text-dark}"
    rounded: "{rounded.control}"
    padding: "0 6px"
    width: "28px"
    height: "28px"
  tab-view:
    textColor: "{colors.text-muted-light}"
    typography: "{typography.label}"
    padding: "0 10px"
    height: "44px"
  tab-view-selected:
    backgroundColor: "{colors.primary-dim-light}"
    textColor: "{colors.primary-text-light}"
  tab-view-dark:
    textColor: "{colors.text-muted-dark}"
    typography: "{typography.label}"
    padding: "0 10px"
    height: "44px"
  tab-view-dark-selected:
    backgroundColor: "{colors.primary-dim-dark}"
    textColor: "{colors.primary-text-dark}"
  chip-filter:
    backgroundColor: "{colors.surface-light}"
    textColor: "{colors.text-muted-light}"
    typography: "{typography.body-small}"
    rounded: "{rounded.capsule}"
    padding: "0 9px 0 8px"
    height: "22px"
  chip-filter-on:
    textColor: "{colors.text-light}"
  chip-filter-dark:
    backgroundColor: "{colors.surface-dark}"
    textColor: "{colors.text-muted-dark}"
    typography: "{typography.body-small}"
    rounded: "{rounded.capsule}"
    padding: "0 9px 0 8px"
    height: "22px"
  chip-filter-dark-on:
    textColor: "{colors.text-dark}"
  field-text:
    backgroundColor: "{colors.surface-light}"
    textColor: "{colors.text-light}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "0 8px"
    height: "24px"
  field-text-dark:
    backgroundColor: "{colors.surface-dark}"
    textColor: "{colors.text-dark}"
    typography: "{typography.body}"
    rounded: "{rounded.control}"
    padding: "0 8px"
    height: "24px"
  surface-inset:
    backgroundColor: "{colors.surface-light}"
    rounded: "{rounded.surface}"
    padding: "16px"
  surface-inset-dark:
    backgroundColor: "{colors.surface-dark}"
    rounded: "{rounded.surface}"
    padding: "16px"
---

# Design System: agents-doctor

## Overview

**Creative North Star: "The Utility Window"**

The product's one web screen is the visual explorer, served locally for one audited folder. It reads as a native macOS utility window, not as a web dashboard. One toolbar at the top carries every view, the product name sits in it as the window title, and content lies in inset grouped surfaces that hairlines divide. Nothing floats at rest: the window colour shows only in the gutters between insets and behind the TreeMap cells.

The window has a light and a dark appearance and follows the system (`prefers-color-scheme`); the page has no switch of its own. Both appearances are one system. Every token has a value for each under the same name, and a rule takes every colour it shows from a token. Greys carry the window, the surfaces and the text. Accent blue marks selection, focus, links and the active view. The state palette marks status and severity, and nothing else is coloured.

The screen is compact: a 13px body on a 1.45 line height, 22px tree rows, 24px fields, 26px push buttons. Control feedback is a fast wash (150ms). Only the inspector, the finding sheet, the toast and the TreeMap zoom move, each in 150 to 200ms.

Four commitments from the product record (`PRODUCT.md`) constrain the screen:

- Colour is never the only signal. Every status and severity keeps its word and its drawn mark beside its colour.
- Secrets stay masked on every surface. The file preview flags a line that a secret rule hit and never shows the value.
- The favicon and the app icon are the author's own drawing. They stay unless the author asks for a change.
- The typeface is the system font stack: San Francisco on Apple devices, the bundled Inter elsewhere (SIL Open Font License, licence shipped beside the file).

### Where the system lives

- `skills/agents-doctor/scripts/ui/static/style.css`: every token, on `:root` for the light appearance and in the `prefers-color-scheme: dark` block under the same names for the dark one. Every rule of this document is in this file.
- `skills/agents-doctor/scripts/ui/static/index.html`: the markup and the inline SVG icons of the toolbar.
- `skills/agents-doctor/scripts/ui/static/app.js`: writes the per-cell scale position of the TreeMap, the chip colours and the overflow state of the panel bodies; it holds no colour of its own.
- `skills/agents-doctor/scripts/ui/static/assets/fonts/InterVariable.woff2`: the one font file. Its licence and a note on its source sit beside it, in the same folder.

### Known limits

The build was exercised in Chromium and Firefox on Windows only. San Francisco, Safari and a screen reader are untested.

**Key Characteristics:**

- One toolbar with eight views, an icon over a label, the active view tinted in the accent.
- Inset grouped surfaces: 10px radius, one hairline border, a flat fill, no shadow.
- Tonal depth: window, alternate strip and surface, divided by hairlines; shadows only under the finding sheet, the toast and the TreeMap tooltip.
- A fixed type scale of five steps (11, 12, 13, 15, 28px), semibold titles, monospace for paths, identifiers and code.
- Compact controls: 24px fields, 26px push buttons, 22px capsule chips, a segmented control, pop-up buttons.
- Two appearances from one set of tokens.
- Drawn icons only: 16px SVG with a 1.5 stroke.

## Colors

Greys carry the window, the surfaces and the text. One blue is the accent. A seven-colour palette marks status and severity. Each value below is given for the light and then for the dark appearance.

### Primary

- **Accent blue** (light #007aff, dark #0a84ff): `--accent`, the frontmatter's `primary`. The focus ring, the text caret, the selected row of the tree and the selected TreeMap cell, the folder icon, the spinner top, the checkbox tint and the total series of the trend chart.
- **Link blue** (light #0040dd, dark #5aa8ff): `--accent-text`. The accent set as text: the label of the active view, path and breadcrumb links, "+N more" rows, fix-step actions and the sort chevron.
- **Fill blue** (light #0066d6, dark #0071e6): `--accent-fill`. The one prominent push button of a view (Run). Its white label keeps 4.5:1 on both fill steps.
- **Fill blue on hover** (light #0071ee, dark #0a74e0): `--accent-fill-hover`. The hover step of that button.
- **Accent wash** (light rgba(0, 122, 255, 0.14), dark rgba(10, 132, 255, 0.16)): `--accent-dim`. The background of the active view and the 3px halo of a focused field.

### State palette

Six state colours come as a pair each: a fill for dots, bars, rings, tints and chart lines, and a text twin for words. Purple comes as text only. The fills are the system colours. The text twins are tuned until each keeps 4.5:1 on the window, on both surfaces and on the selected tint, in both appearances.

- **Red fill** (light #ff3b30, dark #ff453a): `--red`. Fail status, critical severity, the low band of the health score, the tint and border of an error panel.
- **Red text** (light #cd0015, dark #ff8279): `--red-text`. The words and marks of the same states.
- **Orange fill** (light #ff9500, dark #ff9f0a): `--orange`. Warn status, high severity, the middle band of the health score, warning banners and the "DRY RUN" badge.
- **Orange text** (light #c03200, dark #ffb340): `--orange-text`. The words and marks of the same states, and the label on a line that a secret rule flagged.
- **Yellow fill** (light #ffcc00, dark #ffd60a): `--yellow`. Medium severity.
- **Yellow text** (light #8c5800, dark #ffd60a): `--yellow-text`.
- **Green fill** (light #34c759, dark #30d158): `--green`. Pass status and the good band of the health score.
- **Green text** (light #19702f, dark #30d158): `--green-text`. Pass status and "auto", the mark that a fix can be applied.
- **Blue fill** (light #007aff, dark #0a84ff): `--blue`. Low severity. The same values as the accent, under its own token, so that the accent can move without the severity.
- **Blue text** (light #0040dd, dark #5aa8ff): `--blue-text`.
- **Purple text** (light #8944ab, dark #da8fff): `--purple-text`. Unknown status and the symlink mark. Purple is the one state colour with no fill token.
- **Grey fill** (light #8e8e93, dark #98989d): `--gray`. Info severity and the default dot of a badge.
- **Grey text** (light #66666b, dark #a6a6ab): `--gray-text`. The "n/a" status and info severity.

### Neutral

- **Window grey** (light #f5f5f7, dark #1e1e20): `--window`. The page background and the gutters between TreeMap cells. In light it is the grey behind white insets; in dark it is darker than the insets, which keeps the insets coming forward.
- **Inset white** (light #ffffff, dark #2c2c2e): `--surface`. Every inset grouped surface, the inspector and the sheet; fields, bordered push buttons and chips at rest.
- **Alternate strip** (light #ebebed, dark #29292b): `--surface-alt`. The toolbar, the status strip, the chips row, table heads, group header bands, code panes, command blocks, the track of the segmented control, disabled fields.
- **Hover wash** (light #f0f0f2, dark #38383a): `--surface-hover`. Table rows, bordered push buttons and chips under the pointer.
- **Press wash** (light #e0e0e3, dark #424446): `--surface-active`. The same elements while pressed.
- **Selected tint** (light #e2ecff, dark #1d3a5c): `--surface-selected`. The row that holds the keyboard position in the tree and the scan rows picked for a diff. Muted ink on it switches to ink on tint.
- **Ink** (light #1d1d1f, dark #f5f5f7): `--text`. Primary text, and the source of the translucent tints (6% hover, 12% press).
- **Muted ink** (light #66666b, dark #a6a6ab): `--text-muted`. Secondary text, column heads, icons, line numbers. It keeps 4.5:1 on the window, on both surfaces and on the selected tint.
- **Placeholder** (light #66666b, dark #a6a6ab): `--placeholder`. The placeholder of a field, at full opacity. The same value as muted ink, under its own token.
- **Faint ink** (light #86868b, dark #8e8e93): `--text-faint`. Disabled controls and decorative marks only. It is the one text colour that falls below 4.5:1 on the light surfaces.
- **Ink on tint** (light #515154, dark #c7c7cc): `--text-secondary-strong`. Muted ink recoloured where it sits on the selected tint.
- **On accent** (#ffffff, both appearances): `--on-accent`. The label of the prominent button.
- **Scrim** (light rgba(0, 0, 0, 0.25), dark rgba(0, 0, 0, 0.5)): `--backdrop`. The page behind the finding sheet.

### Lines and browser surfaces

- **Hairline separator** (light rgba(0, 0, 0, 0.08), dark rgba(255, 255, 255, 0.10)): `--separator`. The 1px border of every inset surface, the rule between table rows, the edge under the toolbar and the chips row.
- **Border** (light rgba(0, 0, 0, 0.10), dark rgba(255, 255, 255, 0.12)): `--border`. Chips, environment capsules and the toast.
- **Strong border** (light rgba(0, 0, 0, 0.16), dark rgba(255, 255, 255, 0.18)): `--border-strong`. Fields, bordered push buttons, the TreeMap tooltip and the track of the spinner.
- **Selection wash** (light rgba(0, 122, 255, 0.20), dark rgba(10, 132, 255, 0.40)): `--selection`. The background of selected text.
- **Scrollbar thumb** (light rgba(0, 0, 0, 0.26), dark rgba(255, 255, 255, 0.28)): `--scrollbar-thumb`. Thin scrollbars on a transparent track.

Two marks have no value of their own because one rule serves both appearances: `--tint-hover` and `--tint-active` are 6% and 12% of the ink colour, mixed with `color-mix`. They are the hover and press wash of the chrome that has no surface of its own: view tabs, icon buttons, tree rows, breadcrumbs and unselected segments.

### Data colours

- **TreeMap cool** (light #e4e4e9, dark #3a3a3e): `--tm-top`. The fill of the cell with the smallest value.
- **TreeMap hot** (light #93c5ff, dark #1b66c0): `--tm-hot`. The fill of the largest cell. The script writes a position from 0 to 1 on each cell and the stylesheet mixes the two colours by it.
- **Hatch** (light rgba(0, 0, 0, 0.07), dark rgba(255, 255, 255, 0.10)): `--tm-hatch`. The 45° stripes over a directory cell whose size is a partial sum.

Aliases point at the colours above by meaning and add no value: `--sev-critical` to `--sev-info`, `--pass`, `--fail`, `--warn`, `--na`, `--score-good`, `--score-mid`, `--score-bad`, `--series-total`, `--series-critical`, `--series-high`. The script reads the severity aliases and `--pass` to colour the filter chips.

### Status vocabulary

A status badge is a drawn mark (14px) and a word, both in the text colour. It has no fill.

| Status | Text colour | Drawn mark | Word |
| --- | --- | --- | --- |
| pass | green text | check in a circle | pass |
| fail | red text | cross in a circle | fail |
| warn | orange text | triangle with an exclamation mark | warn |
| unknown | purple text | question mark in a circle | unknown |
| not applicable | grey text | dash in a circle | n/a |

The fills of the same names paint other elements: the dot of the "Passed" chip (`--pass`), the tint of an error panel (`--fail`), the tint of a warning banner (`--warn`) and the default dot of a badge (`--na`).

### Severity vocabulary

A severity badge is a 7px dot in the fill colour and the word in the text twin, at weight 500. The same severity appears as a count badge (a letter and a number on a 14% tint of its fill), as a letter in the corner of a TreeMap cell and as the chip that filters it.

| Severity | Fill | Text | Word | Letter |
| --- | --- | --- | --- | --- |
| critical | red | red text | Critical | C |
| high | orange | orange text | High | H |
| medium | yellow | yellow text | Medium | M |
| low | blue | blue text | Low | L |
| info | grey | grey text | Info | I |

A finding row carries its severity in a `data-severity` attribute, and the badges of that row take their tone from it. No bar runs down the side of the row.

The health score has three bands: 80 and above green, 60 to 79 orange, below 60 red. The number is always there beside the colour (the score in the ring, the value at the end of each bar), so no band is read from colour alone. A missing score draws a faint arc and a question mark.

### Named Rules

**The Word And Mark Rule.** Colour never carries a state alone. Every status and severity keeps its word and its drawn mark, and every selection keeps a drawn ring, border or mark beside its tint.

**The Fill And Text Pair Rule.** A state colour set as text is its `-text` twin, never its fill. A state that needs a fill and words gets both tokens.

## Typography

**Display and body font:** the system stack (`-apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif`): San Francisco on Apple devices, the bundled Inter variable font on Windows and Linux.
**Body font:** the same stack.
**Mono font:** `ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Cascadia Mono", "Liberation Mono", monospace`.

**Character:** one sans for every role, with weights 400 to 600 in use (the Inter file covers 100 to 900). Monospace is reserved for paths, identifiers, code, measured values and formulas. Figures in data are tabular. Text is antialiased.

### Hierarchy

- **Display** (semibold, 28px, line-height 1.1, tracking -0.015em): the six stat values of the Overview and the number in the health score ring.
- **Headline** (semibold, 15px, line-height 1.35): the title of a finding in the sheet. The first sentence of an empty state and the title of an error panel take the same size and weight on the inherited line height.
- **Title** (semibold, 13px): the window title, section titles, the inspector path, the headings and the identifier of the sheet.
- **Body** (regular, 13px, line-height 1.45): the default for everything, including table cells and fields. The label of a push button is the same size at weight 500.
- **Body small** (regular, 12px): secondary text and notes, chips, status and severity badges, the status strip, banner text, tooltips, code and monospace cells (an 18px line height in code and in tables). Weight 500 on severity badges and banded group headers, 600 on a chip that is on.
- **Label** (medium, 11px): the view label under its icon (14px line height), column heads (semibold), chart labels, small count badges (semibold), the name band of a TreeMap cell (15px line height) and "/ 100" in the ring. The stat key is the one uppercase text in the system (medium, tracking 0.02em).

The frontmatter carries these roles as `display`, `headline`, `title`, `body`, `body-small`, `label` and `mono`. The stylesheet names its five steps `--text-11`, `--text-12`, `--text-13`, `--text-15` and `--text-28`. 11px is the floor. Letter spacing is set in exactly two places: the 28px values and the uppercase stat keys.

### Named Rules

**The Declared Steps Rule.** A font size is one of the five declared steps, from `--text-11` to `--text-28`. The stylesheet sets no other size, and no text is smaller than 11px.

**The Mono For Data Rule.** Monospace is for paths, identifiers, code, measured values and formulas. Prose, labels and titles stay in the sans.

## Layout

**The window is fixed.** `html` and `body` take the full height and the page never scrolls; panel bodies scroll inside. From the top:

- **Toolbar** (52px minimum): a grid of `1fr auto 1fr`, 12px column gaps, 4px 12px padding, on the alternate strip with a hairline below. Back and forward sit 12px from the left edge. The eight views start 68px from it. The window title (an 18px icon and a 13px semibold name) is centred. Rescan ends the row.
- **Status strip** (28px minimum, 16px side padding): `key: value` pairs that wrap, 12px, the key in muted ink and the value in mono ink.
- **Chips row** (6px 16px 8px): the severity filter, on the alternate strip with a hairline below.
- **Workspace**: a flex row with a 16px gap and 12px 0 0 16px padding. A view is a header (12px 16px 10px) that holds a toolbar row, wrapping with 8px 12px gaps, and a body (10px 16px 16px) that scrolls (under Components, Panel body). The inspector takes the right 46% (380px to 720px) and the full height up to the chips row.
- **Insets** stack with 12px below them, 16px below a table and the instruction diagram and 8px below the environment card. The stat grid is one inset whose cells are divided by 1px gaps that show the separator behind; its columns are `repeat(auto-fit, minmax(max(112px, 16%), 1fr))`.

**Spacing.** The stylesheet sets spacing in literal pixels and enforces no grid. The steps that recur are in the frontmatter (4, 6, 8, 10, 12, 16, 20px). Inset padding is 16px, and the 2px step separates neighbouring toolbar items. Control heights form a ladder: 15px count badges, 18px small capsules, 20px segments, 22px chips and tree rows, 24px fields and table heads, 26px push buttons, 28px toolbar items, 44px views.

**Stacking.** Table heads and group bands stick at 1. A selected TreeMap cell sits at 1, a hovered one at 2 and a focused one at 3. The sheet overlay is at 40, its tooltip at 60 and the toast at 70.

### Responsive

| Width | What changes |
| --- | --- |
| 1319px and below | The views become icon-only, 36px by 40px. The labels stay in the page for assistive technology, visually hidden. The title stays centred. |
| 1100px and below | The inspector leaves the side and stacks under the view: full width, 42vh with a 180px minimum, a hairline border all round, a 10px radius. The workspace becomes a column with a 12px gap and scrolls. The view keeps a 340px minimum height. |
| 900px and below | The toolbar takes two rows: history, title and Rescan above, the eight views spread across below, each 44px minimum wide. |

A table wider than its view does not scroll on its own; the panel body scrolls sideways and takes its overflow state (under Components) while content remains to the right.

### Named Rules

**The Fixed Window Rule.** The page never scrolls. Content scrolls inside its panel body, and below 1100px the stacked workspace is the one exception.

**The One Toolbar Rule.** Every view is reached from the toolbar at the top. There is no side navigation and no second-level menu.

## Elevation & Depth

Depth is tonal. The window sits behind, the alternate strip names the chrome (toolbar, strips, heads, code), the surface comes forward as an inset, and the hover, press and selection washes sit on top. Hairlines separate more than they enclose: an inset has one 1px border and no inner shadow. Shadows exist as two tokens, and three elements use them: the finding sheet, the toast and the TreeMap tooltip.

### Shadow vocabulary

- **Overlay shadow** (light `0 18px 50px rgba(0, 0, 0, 0.22), 0 2px 8px rgba(0, 0, 0, 0.10)`; dark `0 18px 50px rgba(0, 0, 0, 0.55), 0 2px 8px rgba(0, 0, 0, 0.40)`): `--shadow-overlay`, under the finding sheet.
- **Pop shadow** (light `0 4px 14px rgba(0, 0, 0, 0.12), 0 0 1px rgba(0, 0, 0, 0.10)`; dark `0 4px 14px rgba(0, 0, 0, 0.45), 0 0 1px rgba(0, 0, 0, 0.40)`): `--shadow-pop`, under the toast and the TreeMap tooltip.

The pressed segment of the segmented control carries a shadow of its own, written inline: a 1px ring in the strong border colour and a 1px 2px drop in the separator colour.

### Named Rules

**The Inset Rule.** Content sits in an inset grouped surface. Nothing gets a shadow at rest; the three shadows of the system belong to the sheet, the toast and the tooltip.

### Motion

- **Control feedback, 150ms** (`--duration-fast`): background and border colours on hover and press, the colour of a view label, the 90° turn of the disclosure chevron of the tree.
- **Entrances:** the inspector slides 12px in from the right and fades (200ms, `--duration`). The finding sheet scales from 0.98 and fades, and its scrim fades (180ms). The toast fades (150ms). The TreeMap root scales from 0.985 and fades from 0.4 on every render (150ms); the cells do not animate.
- **Spinner:** one turn in 0.8s, linear.
- **Easing:** `cubic-bezier(0.25, 0.1, 0.25, 1)` for everything but the spinner.
- **Reduced motion:** under `prefers-reduced-motion: reduce` every animation and transition is switched off.

## Shapes

- **Radii.** Two tokens: control, 6px (fields, push and icon buttons, command blocks, tooltips, the recommendation and conflict blocks), and surface, 10px (inset cards, tables, the empty state, the inspector when stacked). Values without a token: the finding sheet, 12px; capsules (chips at 11px on a 22px height, the "critical cap" badge at 9px on 18px, the toast and the "DRY RUN" badge at 999px); tree rows and breadcrumbs, 5px; the view tab, 7px; count badges, 8px; bars, 4px.
- **Borders.** 1px hairlines everywhere. The focus ring is the only 2px and 3px line in the system.
- **Form language.** Squared rectangles with small radii. Capsules only for chips, the small status badges and the toast. Fills are flat. The one painted gradient is the scale bar of the TreeMap legend; the overflow fade of a panel body is a mask, not a fill.
- **Icons.** Every icon is drawn on a 16px grid with a 1.5 stroke, round caps and round joins, and takes the colour of its element. Two techniques: inline SVG in the markup (the eight view icons, back, forward, the rescan arrows, close, the magnifier) and CSS masks over inline SVG data URIs for what the stylesheet draws (the status marks, the chevrons, the folder and the document, the empty box, the symlink arrow, the chip check). The pop-up chevrons are a background image with the muted colour baked in, once per appearance. The product icon in the window title is the one raster (18px).

### Browser surfaces

- **Focus ring:** a 3px accent outline, 2px outside the element. Controls whose shape is a tint or a border (views, icon buttons, chips, segments, breadcrumbs, path links) set the offset to 0 or 1px, so the ring follows their corner. Table rows and TreeMap cells draw the ring inset. The tree body draws none: the row that holds the keyboard position carries a 2px inset ring on the selected tint.
- **Text selection:** the selection wash.
- **Caret:** accent blue.
- **Scrollbars:** thin, the thumb in its token colour, a transparent track (`scrollbar-width`, `scrollbar-color`). A panel body in its overflow state gives its own vertical scrollbar an opaque track in the window colour.
- **Placeholders:** placeholder ink at full opacity.
- **Native controls:** `color-scheme: light dark` keeps the system's checkbox and scrollbars in step with the appearance. The checkbox is 13px and tinted with the accent.

### Named Rules

**The Drawn Icon Rule.** An icon is drawn: 16px SVG with a 1.5 stroke, inline or as a mask over an inline data URI. No emoji, no text glyph and no icon font stand in for an icon. The one raster is the product icon.

## Components

### Toolbar and view switcher

The toolbar is the one navigation of the product and its window chrome.

- **Shape:** a 52px strip on the alternate strip with a hairline below. A view is 44px high, 60px minimum wide, with a 7px radius, an icon over an 11px medium label (3px gap), 2px from the next view.
- **States:** a view at rest is muted ink on nothing. Hover is the hover tint and ink, press the press tint. The active view is the accent wash with its label in link blue. The history buttons are faint ink when there is nowhere to go.
- **Window title:** the 18px product icon and the 13px semibold name, centred.

### Push buttons

- **Bordered** (Rescan, Retry, Fix plan): 26px high, 0 12px padding, a 1px strong border, a 6px radius, the surface fill, a 13px medium label. A 16px icon may lead the label. Hover is the hover wash, press the press wash, disabled is faint ink.
- **Prominent** (Run): the one filled button of a view. Fill blue, a white semibold label, no border. Hover is the hover fill, press returns to the fill. Disabled keeps the white label on a 45% mix of the fill and the surface.
- **Icon buttons** (back, forward, close, expand, collapse): 28px high and 28px minimum wide, 0 6px padding, a 6px radius, no fill, a 16px icon or a short word in ink. Hover and press are the ink tints.

### Inputs

- **Text field and search field:** 24px high, 0 8px padding, a 1px strong border, a 6px radius, the surface fill, 13px. Hover darkens the border to 30% ink. Focus turns the border accent blue and adds a 3px accent halo, with no outline. Disabled is the alternate strip with faint ink. The search field carries a 16px magnifier 7px from its left edge.
- **Pop-up button:** a text field with its native appearance removed and two chevrons, 10px wide, 7px from the right edge.
- **Checkbox:** native, 13px, tinted with the accent.

### Segmented control

The metric switch of the TreeMap (Density, Risk, Disk size). A track with 2px padding and an 8px radius lies on the alternate strip and holds 20px segments with a 6px radius, 1px apart, 12px. The pressed segment rises to the surface with a 1px ring and a small drop shadow, at weight 500. An unpressed segment takes the ink tints on hover and press; a disabled one is faint ink.

### Filter chips

Capsules that switch one severity on or off.

- **Shape:** 22px high, an 11px radius, a 1px border, the surface fill, 12px. A 7px dot, the word, a tabular count.
- **Off:** muted ink and a hollow dot (a 1.5px ring in the colour of the chip).
- **On:** the border in the colour of the chip, a 16% tint of it, ink at weight 600, a solid dot and a drawn 12px check. Hover deepens the tint to 24%.
- **Set:** Critical, High, Medium, Low, Info and Passed. Each chip is on or off on its own.

### Status strip

One line under the toolbar with four `key: value` pairs (root, scan, rules, findings): 12px, a muted key and a mono ink value, 20px apart, wrapping when narrow. A long value is cut with an ellipsis and keeps its full text in a title.

### Panel body

The scroll area of a view: 10px 16px 16px, `overflow: auto`. The page itself never scrolls.

- **Overflow state:** while content remains to the right of the body (a table cut at a narrow window), the body carries the class `scrolls-x`. A mask then fades the content out over its last 28px before the vertical scrollbar, so the cut is announced and the reader sees that content continues. The scrollbar itself is not masked and stays fully visible; its track turns opaque, in the window colour. At the end of the content the class is cleared and the fade goes away.
- **Behaviour:** the script checks every panel body when the page starts, when it scrolls, when it resizes and whenever its content changes. It sets the class when more than 1px of content is still to the right and clears it otherwise. It writes the width of a classic vertical scrollbar into the custom property `--sbw` on the body (0px for an overlay scrollbar), so the fade always ends where the scrollbar begins.
- **Clipped, not scrolled:** the body of the TreeMap is clipped (`overflow: hidden`); nothing in it scrolls sideways.

### Inset surfaces

Cards, the stat grid, tables and the search results box.

- **Shape:** a 10px radius, a 1px separator border, the surface fill, clipped to the radius, no shadow.
- **Padding:** 16px in a card (the score block, the chart, the diagram); 8px 14px 9px in a cell of the stat grid.
- **Stat grid:** a label over a value. The label is 11px medium, uppercase, with 0.02em tracking, in muted ink. The value is the display step.
- **Environment capsules:** 22px high, an 11px radius, a 1px border, the surface fill, 12px ink.

### Tables

- **Shape:** an inset surface. Cells 3px 10px on an 18px line height, a hairline under each row and none under the last. Figures are tabular, numeric columns are right-aligned, identifier cells are mono 12px on one line.
- **Head:** 24px, sticks to the top, on the alternate strip, 11px semibold muted ink, never wraps, not selectable.
- **Rows:** hover is the hover wash, press the press wash. The rows the keyboard can reach (findings, recorded scans) draw the focus ring inset.
- **Sorting:** a sortable head takes ink on hover. The sorted head shows a drawn 9px chevron in link blue, up or down.
- **Grouped rows:** one banded header per directory, mono 12px medium on the alternate strip, sticking 26px from the top under the head, its count in muted ink.
- **Width:** heads and identifier cells stay on one line. A table wider than its view is cut by the panel body, which scrolls sideways under its overflow fade.

### Badges

- **Status badge:** a 14px drawn mark and the word, 12px, both in the text colour. No fill.
- **Severity badge:** a 7px dot in the fill and the word in its text twin, 12px medium.
- **Count badge** (tree rows, the inspector, the sheet): a capsule tinted 14% of the severity fill, the letter and the count ("C 2"), 11px semibold, tabular, in the text twin.
- **"critical cap 40":** an 18px capsule, a 14% red tint, red text, 11px semibold.
- **"DRY RUN":** a full capsule, a 14% orange tint, orange text, 11px semibold.
- **"auto":** the fix column of a finding. A drawn check and the word in green text when a fix can be applied, a dash in muted ink otherwise.

### Tree rows

- **Shape:** 22px rows, a 5px radius, 0 6px 0 4px padding, 13px on an 18px line height, children indented 16px.
- **Parts:** a 10px disclosure chevron in muted ink that turns 90° when the folder is open; a 16px document icon in muted ink, or a folder icon in accent blue; the name, cut with an ellipsis; count badges.
- **States:** hover and press are the ink tints. The row that holds the keyboard position is the selection: the selected tint with a 2px inset accent ring, and its muted parts switch to ink on tint. A row with problems sets its name in semibold. A flagged row, one with a critical finding inside, takes a 9% critical tint and 15% on hover. A row kept only because a descendant matches is dimmed: a muted name and an icon at 0.6 opacity.
- **Symlink:** an 11px drawn turning arrow and the word in purple text.
- **"+N more":** the row that loads further children, in link blue, underlined on hover.

### Inspector

A sidebar column with the masked preview of one file.

- **Shape:** the surface, the full height, a hairline on its left, no radius. The header holds the path (13px semibold mono, broken anywhere), count badges and a close icon button.
- **Banner:** a note under the header when the preview was cut (256 KB): the orange tint, 12px, the word "truncated" in orange text.
- **Code:** the alternate strip, mono 12px on an 18px line height. Line numbers sit in a 52px column, muted, not selectable. The line a finding points at takes an 18% accent tint. A line that a secret rule flagged takes a 20% orange tint and a label with the rule's name (11px, orange text on the surface, a 4px radius). When both fall on one line, a 2px inset accent ring marks it. The flagged value stays masked.
- **States:** "binary file" and "Cannot open file" are plain notes in ink.
- **Motion:** slides in 12px and fades in 200ms.

### Finding sheet

A modal sheet over a scrim, for one finding.

- **Shape:** up to 760px wide, 48px from the top, a 12px radius, the surface, the overlay shadow. It scrolls inside when it passes the viewport height minus 96px.
- **Header:** the identifier (13px semibold mono), the severity and status badges, the confidence, a close icon button.
- **Body:** 16px 20px 20px. Section headings 13px semibold, 20px above and 6px below. The title of the finding is the headline step. A path that opens the inspector is a link in mono link blue, underlined on hover. The recommendation sits in a rounded block on the alternate strip. The fix steps are a mono list with hairlines; a command to copy is a block on the alternate strip with a 6px radius.
- **Motion:** the scrim fades and the sheet scales from 0.98, 180ms.

### TreeMap

- **Cells:** rectangles with a 1px border in the window colour, so the gutters show the window. The fill is a mix of the cool and the hot colour by the share of the cell in the largest value. A name band of 15px sits at the top (11px medium, an ellipsis). The letter of the dominant severity sits in a tinted corner badge. Under the disk metric the size follows in 11px.
- **States:** hover outlines the cell in ink. A selected cell has an accent border and an accent ring. Focus adds a 3px inset accent ring and a 4px keyline in ink, because the accent alone disappears on the hottest cells. A directory cell takes a zoom-in cursor. A directory whose size is a partial sum is hatched and marked "≈".
- **Toolbar:** the segmented control, a formula note, and breadcrumbs in link blue with the current folder in semibold ink.
- **Tooltip:** fixed, up to 440px wide, the surface, a 1px strong border, a 6px radius, the pop shadow, mono 12px.
- **Legend:** a line under the map with a scale bar, 110px by 8px, a gradient from the cool to the hot colour.
- **Motion:** the map scales from 0.985 and fades in on every render (150ms).

### Charts

- **Health score:** a 120px ring with an 11px stroke, the track a 10% ink tint and the arc in the band of the score, round caps. The score stands in the display step at its centre, "/ 100" in 11px under it. Beside the ring, one 8px bar per component (a 4px radius) with its name and its value ("65 · w 0.3") in mono.
- **Trend chart:** three lines of 1.6px, total in accent blue, critical in red, high in orange; points ringed in the surface; a hairline grid; 11px labels.
- **Instruction chain:** boxes on the alternate strip with an accent outline, mono 12px names, arrows in muted ink.

### Toast

A capsule fixed 18px from the bottom, centred: the surface, a 1px border, the pop shadow, 9px 18px padding, 12px ink, up to 560px wide. It fades in (150ms) and leaves after 4.5 seconds.

### Empty, loading and error states

- **Empty state:** an inset surface with a drawn dashed box (18px) at its left and 15px 18px 15px 46px padding. The first sentence is ink at the headline step; what follows is 12px muted ink, often the command that fills the view. Inside the TreeMap and the diagram it has no border.
- **Loading:** a 14px spinner (a 2px ring in the strong border colour with an accent top) and a muted sentence, with 16px 4px padding.
- **Error panel:** up to 560px wide, 14px 16px padding, a 10px radius, a 45% red border on an 8% red tint. "Failed to load" at the headline step in red text, the message in mono 12px, and a bordered Retry button.
- **Banner:** a strip in the 14% orange tint, 12px ink; the word that names the warning is in orange text. The simulate view wraps it in an inset with a 30% orange border.

## Do's and Don'ts

### Do:

- **Do** place content in an inset grouped surface: the `surface` fill, a 10px radius and a 1px `separator` border, on the `window` background.
- **Do** let a panel body scroll sideways for content wider than its view; its overflow fade marks the cut.
- **Do** name a state with its word and its drawn mark, and set its text in the `-text` token of its colour, never in a fill.
- **Do** take hover, press and selection from the shared tokens (`surface-hover`, `surface-active`, `surface-selected`, `tint-hover`, `tint-active`) and give every interactive element the 3px focus ring.
- **Do** take sizes from the five type steps and set paths, identifiers and code in the mono stack.
- **Do** draw a new icon as 16px SVG with a 1.5 stroke and round caps, filled with the colour of its element.
- **Do** add a new token in both appearances, under one name, on `:root` and in the dark block.
- **Do** keep control transitions at 150ms and switch them off under `prefers-reduced-motion: reduce`.

### Don't:

- **Don't** convey a status, a severity or a selection by colour alone.
- **Don't** show the value of a secret on any surface. Flag the line and keep the value masked.
- **Don't** give a resting element a shadow. Shadows belong to the finding sheet, the toast and the TreeMap tooltip.
- **Don't** use an emoji, a text glyph or an icon font as an icon.
- **Don't** set a font size outside the declared steps, or any text below 11px.
- **Don't** set prose in monospace.
- **Don't** add a second accent or re-tint the state colours. One blue is the accent.
- **Don't** replace the favicon or the app icon. They are the author's own drawing and change only on the author's request.
- **Don't** write a visible colour into a rule. Use the token.
