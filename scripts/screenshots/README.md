# README screenshots

`docs/00.png`, `docs/01.png`, `docs/02.png` and `docs/03.png` are produced by the scripts in this directory from a
**synthetic** run. No real account, collector or AWS API is involved (finding F-134: the earlier images
showed identifiers from a real-looking environment).

| Image | View |
|---|---|
| `docs/00.png` | Brief: the verdict, the headline numbers, the top attack paths, internet exposure, detection posture and coverage, right after the run zip is opened |
| `docs/01.png` | Explore: the `demo-web-1` EC2 instance, chosen through the search box, its neighbourhood on the canvas and its details in the drawer |
| `docs/02.png` | Attack paths: the external partner account's 6-step route to the account administrator, selected, with its kill-chain canvas in the drawer |
| `docs/03.png` | Map: the kill-chain map of every route (ways in, footholds, escalation, admin, data reached), with the top key pivot pinned so its routes light up |

## Regenerate

```sh
scripts/screenshots/capture.sh                 # writes docs/00.png docs/01.png docs/02.png docs/03.png
scripts/screenshots/capture.sh --out-dir /tmp/shots --view detail   # one view elsewhere
```

You need the repository venv (`.venv`) and Google Chrome; the default path is
`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, and `--chrome PATH` or `$CHROME` overrides it.
The output is deterministic: on the same machine and Chrome version, the same code gives byte-identical images.
Fonts and Chrome's renderer can differ elsewhere.

## How it works

1. `make_demo_report.py OUT --zip` builds a v2 run with the test-suite builders
   (`tests/support/report_builder.py`). It then runs `aws-enumerator analyze` on the run and zips it
   with `aws-enumerator package`.
   - **Placeholders only:** the target account is `111122223333`, an external partner account is
     `999999999999`, names are `demo-*`, EC2-family ids are hexadecimal placeholders, and the public IP is
     from TEST-NET-3 (`203.0.113.0/24`).
   - **The estate:** IAM users, groups and roles; S3 with one public bucket; a public web instance with an
     open security group and IMDSv1; a Lambda function URL with no auth; Secrets Manager and KMS; an EKS
     cluster with IRSA, RBAC and a privileged pod; an internet-facing load balancer; and a cross-account
     trust with no ExternalId.
   - **Escalation paths:** PassRole to Lambda, CreatePolicyVersion, UpdateFunctionCode, and
     SSM SendCommand into an instance.
   - **Guard:** the script fails if any file it wrote, zip members included, holds a 12-digit number
     other than the two demo accounts.
2. `capture.py --zip RUN.zip --out-dir DIR` captures the views.
   - **Server:** it serves the dashboard with the real `aws-enumerator dashboard --port 0 --no-browser`
     (127.0.0.1, with the shipped CSP and Host allow-list).
   - **Browser:** it starts headless Chrome with a throw-away profile. Name resolution is limited to
     127.0.0.1, other traffic goes to a dead proxy, and background networking is off.
   - **Driving the page:** it uses the DevTools protocol (`websocket-client`, which is already in the venv
     as a dependency of `kubernetes`). It opens the zip through the page's own "Open zip or graph.json"
     input and then uses the page's search box, its tabs and a table row.
     The zip goes through the real loader, so the header shows "digest verified".
   - **Failure checks:** it fails if the page records a script error, a CSP violation or a load problem,
     or requests anything outside the dashboard origin. Chrome's own `/favicon.ico` probe, which the server
     answers with 404, is the one exception.
   - **Output:** each PNG is re-encoded with only the critical chunks: `IHDR`, `PLTE`, `IDAT` and `IEND`.
     No text, time, EXIF or colour-profile metadata survives.

The shipped dashboard has no demo code path. The only thing the harness adds to the page is a
fixed-seed `Math.random`, installed through DevTools before the page's own scripts run (`SEEDED_RANDOM`). It
makes the force-directed layout repeatable.

The viewport is 1800x1200, so the Brief and the drawers show without scrolling.

`tests/python/docs/test_screenshots.py` checks the following, offline and without Chrome:
- the images are valid PNGs with no metadata chunks and the harness's dimensions;
- none of them is one of the retired images;
- the demo run contains only the two placeholder accounts and the labels the harness looks for.

## Checklist for any image added to the docs

1. Make it from a synthetic or fixture report, never from an engagement. Use placeholder accounts only
   (`123456789012`, `111122223333`, `999999999999` or `000000000000`), `demo-*` / `example-*` names, and
   `example.com` / TEST-NET addresses.
2. Look at the image at full resolution, and zoom into dense areas and side panels. Check for account IDs,
   ARNs, role and permission-set names (including SSO hash suffixes), key or resource UUIDs, bucket names,
   hostnames, emails, profile names and file paths. Cropping or blurring is not enough if the data was real.
3. Strip the metadata: `strip_png()` in `capture.py` keeps only the critical chunks. For other tools, check that
   no `tEXt`, `zTXt`, `iTXt`, `eXIf` or `tIME` chunk is left.
4. Keep it small (well under 1 MB) and at a size where the text is legible at 100 % zoom.
5. Remember that replacing a committed image does not remove it from git history. The images that F-134
   replaced are still in commits `f23b624` and `403fad4`. Purging them (`git filter-repo` and a force-push, which
   forks and clones survive) is the repository owner's decision.
