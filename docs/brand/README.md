# Brand assets

The product is **OTSec**. `otsec-master.png` in this directory is the supplied
artwork. Everything the console serves is **derived from it and committed**, so
a deployment needs nothing but the repository.

```bash
python tools/build_brand_assets.py            # rebuild
python tools/build_brand_assets.py --check    # fail if the committed assets drift
```

That tool needs Pillow. It is declared in `ot_scanner/requirements-dev.txt` and
deliberately **not** in `requirements.txt` — the container never builds assets.

| Derived file | Used by | Renders at | Size |
|---|---|---|---|
| `console/public/otsec-logo.png` | the sign-in panel (`.login-logo`) | 22rem wide, 15rem under 860px | 152 KB, 1000×747 |
| `console/public/otsec-mark.png` | the shell header (`.brand-mark`) and both favicons | 26px, and 16px in a tab | 27 KB, 256² |

The mark is the **shield alone** — cropped tight and centred on a square of
field. Cropping the lockup to a square directly drags the peripheral PLC / RTU /
SCADA glyphs in, and at 16px those are indistinguishable from dirt. The build
finds the shield by column profile: the glyphs are short spikes, the shield is a
sustained run.

## ⚠️ Do not key the field out

The master is ink on a flat blue field, and **that field is not incidental
packaging.**

Un-mixing a pixel against a target ink projects it onto that ink's axis, so any
ink *lighter* than the field yields a negative coefficient, clamps to zero, and
is written fully transparent. This artwork has three such regions — the shield's
silver bevel, the pale blue circuit traces, and the peripheral device glyphs.
Keying the field out erases all three and leaves a floating navy blob.

MonitorRisk shipped exactly this mistake: its build keyed a cream field out from
under a white "Risk", and the console rendered the product as **"Monitor"** —
with a valid RGBA PNG, correct dimensions and a green suite, because the only
assertion checked the file's colour type.

And no page colour would fix it, because the lockup carries dark navy ink *and*
a silver bevel — navy needs a light ground, silver needs a dark one. So the
lockup **keeps its field** and is a self-contained brand panel. The panel behind
it is painted the same value, `--brand-field` in `console.css`, and a test
asserts the hex still equals the asset's own background pixel. Without that, the
two drift and the sign-in page shows a rectangle seam around the logo.

Text on that panel takes `--brand-ink`, the wordmark's navy read out of the
artwork. Measured on `#82c2e5`:

| | ratio | |
|---|---:|---|
| `--brand-ink` `#23254e` | **7.47:1** | passes AA |
| the console's `--ink` | 1.60:1 | invisible |
| the console's `--ink-dim` | 1.31:1 | invisible |

Reusing the console's own text colour would have put unreadable text on the one
page that has to inspire trust. A test holds the ratio at 4.5:1.

## What the build does

1. **Detects the field** from the border ring, which is field by construction.
2. **Flattens** every near-field pixel onto exactly that value. The master is a
   lossy render whose "flat" background is ±14 levels of noise across 71% of the
   image.
3. **Quantises to a 256-colour palette.** Measured: an RMS error of 2.88/255
   against truecolour, and 457 KB → 152 KB. Downscaling instead is worse on both
   counts — 800px truecolour is 303 KB at RMS 5.16 — because the cost here is
   the render's gradient noise, not its resolution. The field survives
   quantisation as exactly its own value, which is what lets the CSS match it.
4. **Checks the geometry** it detected against measurements recorded in the
   script, and stops if a master lands outside them. A re-supplied image that
   crops through the middle of the wordmark would otherwise pass every other
   test.

Drift is compared as **pixels, not encoded bytes**. PNG output differs between
Pillow and zlib versions and the CI matrix spans four Python legs that do not
resolve to the same Pillow, so a byte check would go red on a runner upgrade —
which is how a real signal gets trained away.

## Replacing the artwork

Drop the new file in as `otsec-master.png`, run the build, and commit what it
writes. If the build stops on the geometry gate, the new image is composed
differently: **re-measure it and update `EXPECT` in the script** rather than
widening the tolerance, since the gate is the only thing standing between a
mis-crop and a green suite.

## What a rename touches

Recorded because the OTSec rename was done by hand and the list is not obvious.
Beyond the pages and the artwork:

- `ot_server/totp.py` — `ISSUER`, which is what an authenticator writes into a
  permanent entry on an operator's phone
- `ot_server/authn_api.py` — `COOKIE_NAME`; changing it signs out every live
  session, which is acceptable exactly once, at a rename
- `ot_server/authn.py` — `OTSEC_BOOTSTRAP_USER` / `OTSEC_BOOTSTRAP_PASSWORD`
- `deploy/demo/` — image name, `/var/lib/otsec`, the unix account
- `ot_scanner/collector/content.py` — temporary-file prefixes

`tests/test_branding.py` scans every shipping surface for the retired name so
the next one is not done by hand. It deliberately does not scan `docs/`: a
history that cannot name what it changed from is a worse history.
