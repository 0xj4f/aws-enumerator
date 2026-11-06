# Vendored dashboard libraries

The dashboard's two third-party libraries are kept here so it works offline and can load them with Subresource Integrity (F-089).

- **Status:** files vendored and pinned in Wave 0. Since Wave 2, `index.html` loads both libraries from `vendor/` with `integrity=` (the values below), and the licence texts of the libraries bundled inside `jszip.min.js` are here too (Wave 2, owner-approved download).
- **Do not edit these files by hand.** They are checked byte for byte by `scripts/vendor_dashboard_libs.py --verify` and `tests/js/helpers/vendor.test.js`.

## Files

Each row is machine-checked: size in bytes, SHA-256 in hex, and the SRI value (`sha384-` plus the base64 digest).

| File | Library | Version | Bytes | SHA-256 | SRI (sha384) |
|---|---|---|---|---|---|
| `jszip.min.js` | JSZip | 3.10.1 | 97630 | `acc7e41455a80765b5fd9c7ee1b8078a6d160bbbca455aeae854de65c947d59e` | `sha384-+mbV2IY1Zk/X1p/nWllGySJSUN8uMs+gUAN10Or95UBH0fpj6GfKgPmgC5EXieXG` |
| `cytoscape.min.js` | Cytoscape.js | 3.30.4 | 373734 | `1bb5340e549511e111b31e5684872c949ad33d40ea5dba0ad8e7d90c62c7b3b9` | `sha384-H3uzGzTfGHUAumB8+s4GEdfFwzAceN9wCCndN8AXubWKFIPuBSWKKtWDx7RhSf/z` |
| `LICENSE-jszip.txt` | JSZip licence (MIT option) | 3.10.1 | 1250 | `6adc57e6e6603ae60fddeac2298736b97344e8408c8ce00b46a166daf846844d` | `sha384-2MAIB7NW4GMSe5qYLOsK4l/wXNaEbPZRCuoYucGTcJIdhOsNawzWjJB33PJlHvjk` |
| `LICENSE-cytoscape.txt` | Cytoscape.js licence (MIT) | 3.30.4 | 1082 | `a29c0d78a54de204b78357976c3d272a573b8592d0478b9db07af3f1da31a65a` | `sha384-LUh9mwHvIOWTWpP1blxMxOOcD46mFUf39koThV3Sqa7Fp28hInuBVWC2FZkjTN3s` |
| `LICENSE-immediate.txt` | immediate licence (MIT), in jszip.min.js via lie | 3.0.6 | 1115 | `809e66de579fb7d92503848bbe6d1f348f4f6521a71e5d294fe7cc0c87a3b4ff` | `sha384-/xyw2DsttZdT/zBUaGcKYUOM+K4hBGlHzD836zw7RFbQtMRtqpP0JoLsN0TQHjCO` |
| `LICENSE-lie.txt` | lie licence (MIT), in jszip.min.js | 3.3.0 | 1084 | `5c81b0caa98593408b03125efa25efe622341ed87ae55561968828cd887d64a4` | `sha384-I8WaeUOMIBl8FNhjd69SpsreP5QPhaX0UyIietCEmZjBLTxMxi9dQ2Tot6Z8kt5K` |
| `LICENSE-pako.txt` | pako licence (MIT; package declares MIT AND Zlib), in jszip.min.js | 1.0.11 | 1104 | `a04665b3b2de56c66730c1f720f528175739e4104f79073614aa611da1e85539` | `sha384-9tg5LwdfxM6Fpdp6Sep9VI0qXS7Eg5gQRPvNrfV3DKIkVVL3EwSK2atu+zRoEwJg` |
| `LICENSE-readable-stream.txt` | readable-stream licence (MIT), declared by JSZip, not in the browser bundle | 2.3.7 | 2337 | `ec62dc96da0099b87f4511736c87309335527fb7031639493e06c95728dc8c54` | `sha384-WuCdzfyCEYQ/jP2YVXZN+pVZOK0sC2HYhn0iSEdHbofdtbQxhUm1hklXQfVKmMZ2` |
| `LICENSE-setimmediate.txt` | setimmediate licence (MIT), in jszip.min.js | 1.0.5 | 1103 | `c4b4ad3a5746f1f5249a6dd90396ec519264e1bb02e01e48a6522c48a3a97cb4` | `sha384-iMm/Sk6ItiiCw5HPIIHFHDxXqMxU4vaJATBpaYWDpEl/ohgtDfqf1XcbEIBDGlDB` |

**SHA-512 (base64, SRI form):**

- `jszip.min.js`: `sha512-XMVd28F1oH/O71fzwBnV7HucLxVwtxf26XV8P4wPk26EDxuGZ91N8bsOttmnomcCD3CS5ZMRL50H0GgOHvegtg==`
- `cytoscape.min.js`: `sha512-xpXUCbrkyJCwC5noJXZqec9rSXdRgFfDoL7Q9/pCPe54Y04OlqwPobMcNuA5NPJ7DRR51OIr6xcOH2wUspyKDQ==`

**In `index.html` (since Wave 2):**

```html
<script defer src="vendor/jszip.min.js" integrity="sha384-+mbV2IY1Zk/X1p/nWllGySJSUN8uMs+gUAN10Or95UBH0fpj6GfKgPmgC5EXieXG"></script>
<script defer src="vendor/cytoscape.min.js" integrity="sha384-H3uzGzTfGHUAumB8+s4GEdfFwzAceN9wCCndN8AXubWKFIPuBSWKKtWDx7RhSf/z"></script>
```

## Sources

### JSZip 3.10.1

| Item | Value |
|---|---|
| cdnjs | `https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js` |
| npm tarball | `https://registry.npmjs.org/jszip/-/jszip-3.10.1.tgz` (195083 bytes) |
| npm metadata | `https://registry.npmjs.org/jszip/3.10.1` |
| npm `dist.integrity` | `sha512-xXDvecyTpGLrqFrvkrUSoxxfJI5AH7U8zxxtVclpsUtMCq4JQ290LY8AW5c7Ggnr/Y/oK+bQMbqK2qmtk3pN4g==` |
| npm `dist.shasum` | `34aee70eb18ea1faec2f589208a157d1feb091c2` |
| Tarball member | `package/dist/jszip.min.js` |
| Licence | `(MIT OR GPL-3.0-or-later)`. This project uses it under **MIT**. |
| Licence file | `LICENSE-jszip.txt` is the dual-licence preamble and the MIT section of `package/LICENSE.markdown`, verbatim. The GPLv3 text is left out because we do not use that option. |

The minified bundle also contains code from JSZip's dependencies. Its header names pako (MIT), and `package.json` lists `lie`, `pako`, `readable-stream` and `setimmediate`. Their licence texts are not in the JSZip tarball; they were added in Wave 2 from each dependency's own npm tarball (next section).

### Licences of JSZip's bundled dependencies (Wave 2)

`jszip.min.js` is a browserify bundle. Its module table (read from the file) contains **pako**, **lie**, **immediate** (required by lie) and **setimmediate**. `readable-stream` is declared in JSZip's `package.json`, but JSZip's `browser` field maps it to `lib/readable-stream-browser.js` (`require("stream")`), which the bundle leaves out (`{stream: void 0}`); its licence is kept anyway because the dependency is declared.

Version choice: each range is resolved to the newest release that matched it when JSZip 3.10.1 was published (registry time 2022-08-02), which is what the release build resolved: pako `~1.0.2` -> 1.0.11, lie `~3.3.0` -> 3.3.0, immediate (lie's `~3.0.5`) -> 3.0.6, setimmediate `^1.0.5` -> 1.0.5, readable-stream `~2.3.6` -> 2.3.7 (2.3.8 is from 2023).

| Package | Version | Range (required by) | Tarball | npm `dist.integrity` | npm `dist.shasum` | Licence file in the tarball |
|---|---|---|---|---|---|---|
| immediate | 3.0.6 | `~3.0.5` (lie 3.3.0) | `https://registry.npmjs.org/immediate/-/immediate-3.0.6.tgz` | `sha512-XXOFtyqDjNDAQxVfYxuF7g9Il/IbWmmlQg2MYKOH8ExIT1qg6xc4zyS3HaEEATgs1btfzxq15ciUiY7gjSXRGQ==` | `9db1dbd0faf8de6fbe0f5dd5e56bb606280de69b` | `package/LICENSE.txt` |
| lie | 3.3.0 | `~3.3.0` (jszip 3.10.1) | `https://registry.npmjs.org/lie/-/lie-3.3.0.tgz` | `sha512-UaiMJzeWRlEujzAuw5LokY1L5ecNQYZKfmyZ9L7wDHb/p5etKaxXhohBcrw0EYby+G/NA52vRSN4N39dxHAIwQ==` | `dcf82dee545f46074daf200c7c1c5a08e0f40f6a` | `package/license.md` |
| pako | 1.0.11 | `~1.0.2` (jszip 3.10.1) | `https://registry.npmjs.org/pako/-/pako-1.0.11.tgz` | `sha512-4hLB8Py4zZce5s4yd9XzopqwVv/yGNhV1Bl8NTmCq1763HeK2+EwVTv+leGeL13Dnh2wfbqowVPXCIO0z4taYw==` | `6c9599d340d54dfd3946380252a35705a6b992bf` | `package/LICENSE` |
| readable-stream | 2.3.7 | `~2.3.6` (jszip 3.10.1) | `https://registry.npmjs.org/readable-stream/-/readable-stream-2.3.7.tgz` | `sha512-Ebho8K4jIbHAxnuxi7o42OrZgF/ZTNcsZj6nRKyUmkhLFq8CHItp/fy6hQZuZmP/n3yZ9VBUbp4zz/mX8hmYPw==` | `1eca1cf711aef814c04f62252a36a62f6cb23b57` | `package/LICENSE` |
| setimmediate | 1.0.5 | `^1.0.5` (jszip 3.10.1) | `https://registry.npmjs.org/setimmediate/-/setimmediate-1.0.5.tgz` | `sha512-MATJdZp8sLqDl/68LfQmbP8zKPLQNV6BIZoIgrscFDQ+RsvK/BxeDQOgyxKKoh0y/8h3BqVFnCqQ/gd+reiIXA==` | `290cbb232e306942d7d7ea9b83732ab7856f8285` | `package/LICENSE.txt` |

Each `LICENSE-<package>.txt` is the listed tarball member, **verbatim** (2026-10-16): the registry packument and the tarball went into a new, empty quarantine directory per package; the tarball's SHA-512 matched the registry `dist.integrity` and its SHA-1 the `dist.shasum`; every member was a regular file or directory under `package/` (no absolute paths, no `..`); only the licence member was read, in memory; nothing was extracted by path or executed.

### Cytoscape.js 3.30.4

| Item | Value |
|---|---|
| cdnjs | `https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.30.4/cytoscape.min.js` |
| npm tarball | `https://registry.npmjs.org/cytoscape/-/cytoscape-3.30.4.tgz` (1135049 bytes) |
| npm metadata | `https://registry.npmjs.org/cytoscape/3.30.4` |
| npm `dist.integrity` | `sha512-OxtlZwQl1WbwMmLiyPSEBuzeTIQnwZhJYYWFzZ2PhEHVFwpeaqNIkUzSiso00D98qk60l8Gwon2RP304d3BJ1A==` |
| npm `dist.shasum` | `3404da0a159c00a1a3df2c85b2b43fdc66a0e28e` |
| Tarball member | `package/dist/cytoscape.min.js` |
| Licence | MIT |
| Licence file | `LICENSE-cytoscape.txt` is `package/LICENSE`, verbatim. The upstream file has no trailing newline. |

## How the files were verified (2026-10-15)

The owner approved this one-time download. Nothing downloaded was executed before these checks passed.

1. **Downloaded to quarantine.** Each source went into its own new, empty directory under the run's `quarantine/` (`<lib>-cdnjs/`, `<lib>-npm/`), over HTTPS only.
2. **Tarballs checked against the registry.**
   - Each tarball's SHA-512 matched `dist.integrity` from the registry metadata (computed with `openssl dgst -sha512 -binary | openssl base64 -A`).
   - Its SHA-1 matched `dist.shasum`.
   - The metadata also lists one registry signature per package. It was **not** checked offline.
3. **Tarballs inspected before extraction.** Every entry was a regular file under `package/`, with no absolute paths and no `..`. They were extracted with `tar --no-same-owner --no-same-permissions` inside the quarantine directory.
4. **Sources compared.** The cdnjs file and the tarball's `package/dist/*.min.js` were **byte-identical** for both libraries (`cmp`; same SHA-256). There was no divergence, so no source had to be preferred.
5. **Copied in.** The npm-integrity-verified file was copied here, and the hashes above were computed from these copies.

**After verification, observed in Node 20 (pinned by `tests/js/helpers/vendor.test.js`):**

- Both UMD builds load with `require()`, and their version strings match.
- Cytoscape runs with `headless: true`.
- In the constructor, Cytoscape silently drops duplicate element IDs (the first one wins). It throws for an edge whose endpoint is missing.

## Re-checking and refreshing

- **Offline check** (no network):

  ```sh
  .venv/bin/python -I scripts/vendor_dashboard_libs.py --verify
  ```

  It re-hashes every file here against the pins in the script and checks that this document lists the same values.
- **Re-download** (network; needs owner approval each time; not run by tests):

  ```sh
  .venv/bin/python -I scripts/vendor_dashboard_libs.py --fetch --quarantine <new empty dir>
  ```

  It downloads both sources and the registry metadata, verifies `dist.integrity`, reads only the needed tarball members in memory, and compares cdnjs, npm and the pins; it also re-fetches the dependency licence texts from their npm tarballs (`--licences-only` fetches only those). Add `--install` to copy the files here, which happens only if every check passed.
- **Upgrading a version** means changing the pins in the script, re-running `--fetch --install`, and updating this file and the `index.html` `integrity=` values together.

## Open items

- **pako's zlib notice.** pako's `package.json` declares `(MIT AND Zlib)`: its `LICENSE` file (copied here) is MIT, and the zlib-derived files (`lib/zlib/*.js` in the pako 1.0.11 tarball) carry the zlib licence notice in their header comments, which the minified JSZip bundle does not keep. The zlib licence asks that the notice stays in source distributions; an acknowledgement in product documentation is "appreciated but not required". Whether to add that notice (verbatim from those headers) is left to the owner, because only LICENSE files were approved for copying.
- **Registry signatures.** These were not verified, because that needs the registry's public keys, which means network access.
