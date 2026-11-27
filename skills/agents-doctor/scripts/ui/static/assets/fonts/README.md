# Inter

`InterVariable.woff2` is the web font file of Inter, the typeface by
Rasmus Andersson. It is one variable font: a single file covers every
weight from 100 to 900.

| Field | Value |
| ----- | ----- |
| Source | <https://rsms.me/inter/font-files/InterVariable.woff2> |
| Release | 4.1 (the font reports `Version 4.001;git-9221beed3`) |
| Downloaded | 2026-11-27 |
| Size | 352240 bytes |
| SHA-256 | `693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3` |
| License | SIL Open Font License 1.1, full text in `LICENSE-Inter.txt` |

The file is unmodified. Its SHA-256 equals the one of
`docs/font-files/InterVariable.woff2` at tag `v4.1` of the source
repository, <https://github.com/rsms/inter>.

## Use in the stylesheet

`../../style.css` declares the font:

```css
@font-face { font-family: "Inter"; font-style: normal; font-weight: 100 900; font-display: swap; src: url("./assets/fonts/InterVariable.woff2") format("woff2"); }
```

`index.html` preloads the file, so every system downloads it.
`--font-sans` lists `-apple-system` before `Inter`: Apple systems render
with the system font and leave Inter unused, Windows and Linux render
with Inter.

## Replacing the file

Download the new release from the source above, check that it starts
with the four bytes `wOF2`, compute its hash, then update the table:

```
python -I -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" InterVariable.woff2
```
