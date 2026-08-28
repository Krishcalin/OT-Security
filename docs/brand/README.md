# Brand assets

The product is **OTSec**. This directory documents how its artwork reaches the
console, and what to be careful about when the supplied logo lands.

## What is committed today

| File | Used by | Size it renders at |
|---|---|---|
| `console/public/otsec-logo.svg` | the sign-in page (`.login-logo`) | 22rem wide, 15rem under 860px |
| `console/public/otsec-mark.svg` | the shell header (`.brand-mark`) and both favicons | 26px, and 16px in a tab |

**Both are drawn stand-ins, not the supplied artwork.** They match the
product's visual language — shield, eye, pylons, the circuit blue the console
already uses — so the console is not missing a brand while the real files are
in transit. Replace them; they exist to be replaced.

## Shipping the supplied artwork

Save the supplied PNG as `console/public/otsec-logo.png`, crop a square
shield-only version to `console/public/otsec-mark.png`, then change three
references:

```
console/public/login.html    <img class="login-logo" src="/otsec-logo.png" ...
console/public/index.html    <img class="brand-mark" src="/otsec-mark.png" alt="" />
console/public/index.html    <link rel="icon" href="/otsec-mark.png" />
console/public/login.html    <link rel="icon" href="/otsec-mark.png" />
```

`tests/test_branding.py::test_every_asset_a_page_references_exists` fails if a
reference points at a file that is not there, so a typo in that swap is caught
here rather than by an operator looking at a broken image where the brand
should be — on the one page where a missing logo reads as a phishing site.

Sizes to hit: the lockup renders 352 CSS px wide, so **≥ 704px** for a 2×
display; the mark renders at 26px and 16px, so a **128px square** is ample. The
lockup is loaded on every visit to the sign-in page — keep it under ~200 KB.

## ⚠️ Do not key the field out of the lockup

This is the lesson MonitorRisk paid for, and the OTSec artwork is the same kind
of image: ink on a flat coloured field rather than ink on transparency.

Keying such a field out looks like tidying and is not. The un-mixing that makes
a background transparent projects each pixel against the target inks, and any
ink **lighter** than the field clamps to zero and is written fully transparent.
MonitorRisk's build did exactly that to a white "Risk", and the console rendered
the product as "Monitor" — with a valid RGBA PNG, correct dimensions and a green
suite, because the assertion only checked the file's colour type.

The deeper problem is that there is no page colour on which a keyed lockup
reads. Measured on MonitorRisk's two inks:

| | dark ink | light ink |
|---|---|---|
| on its own field | 7.29:1 | 1.95:1 | both legible |
| on the dark console `#0f1419` | **1.30:1** | 18.51:1 | dark ink invisible |
| on a light panel | 12.71:1 | **1.12:1** | light ink invisible |

So **the lockup keeps its own field** and is a self-contained brand panel. If
that field needs to meet the console's background, paint the panel behind it the
same value rather than erasing it from the image. The `.login-brand-side` panel
is where that would go.

The mark may be keyed, if and only if it contains no ink lighter than its field
— shield outline and pulse only, no wordmark.

## What a rename touches

Recorded because this one was done by hand and the list is not obvious. Beyond
the pages and the artwork:

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
