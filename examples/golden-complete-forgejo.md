# VersionSec — https://synthetic.invalid/team

Schema: forgeguard.assessment.v1 | Profile: standard | Policy: private
Score: 100 (A)
Requests: 5; incomplete: none
Skipped by profile: FG-ROOT-HTTP

Product and version provenance: {"declared\_product": "forgejo", "declared\_version": null, "declared\_version\_marker": null, "normalized\_version": "15.0.8", "observed\_product\_marker": null, "observed\_version": "15.0.8", "product\_conflict": false, "product\_source": "operator-declared", "provider\_revision": "1", "support": "qualified", "version\_conflict": false}

Catalog: {"coverage": "Curated records only; absence is not evidence of safety.", "sha256": "1acebe5d0e06891909237623912f224bce1ac886157eb402dfb9e925dc6a15f3", "verified\_at": "2026-09-11", "version": "2026-09-11.1"}

## FG-ANON — Allowlisted API HTTP responses
pass | assessed | applicable
Source: anonymous-http
Observed: {"/api/v1/repos/search?limit=1": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}, "/api/v1/users/search?limit=1": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}}
Expected: Private intent: review anonymous HTTP 200; public/unspecified: informational.
Reason: Only the named path statuses were observed. HTTP 200 may be a login page, proxy error or empty API; it does not prove data access. Unknown responses remain incomplete even alongside a warning.
Action:
References: https://codeberg.org/forgejo/forgejo/src/tag/v16.0.4/templates/swagger/v1\_json.tmpl

## FG-FJ-TEMPLATE-20260910 — Template initialization security update version posture
pass | assessed | applicable
Source: catalog:forgejo
Observed: {"outcome": "fixed", "record\_version": 1, "version": "15.0.8"}
Expected: Version within the explicit fixed range for this advisory.
Reason: Version is within the catalog's explicit fixed interval.
Action:
References: https://codeberg.org/forgejo/forgejo/src/branch/forgejo/release-notes-published/15.0.8.md, https://codeberg.org/forgejo/forgejo/src/branch/forgejo/release-notes-published/16.0.4.md

## FG-HTTP — Transport and HTTP protection observations
info | assessed | applicable
Source: anonymous-http
Observed: {"/api/v1/repos/search?limit=1": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}, "/api/v1/users/search?limit=1": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}, "/api/v1/version": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": false, "https": true, "json": true, "nosniff": false, "status": 200}, "/explore/repos": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}, "/v2/": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}}
Expected: Verified HTTPS; header summaries apply only to returned response types.
Reason: HTTPS means certificate verification on this request, not a TLS audit. X-Frame-Options only describes embedding protection for HTML; nosniff is a limited response observation. HSTS/CSP presence is informational and is not policy validation. Reverse proxies may supply headers. No penalty from presence alone.
Action:
References:

## FG-REG — OCI registry-root HTTP response
pass | assessed | applicable
Source: anonymous-http
Observed: {"/v2/": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}}
Expected: Private intent: review anonymous HTTP 200; public/unspecified: informational.
Reason: Only the named path statuses were observed. HTTP 200 may be a login page, proxy error or empty API; it does not prove data access. Unknown responses remain incomplete even alongside a warning.
Action:
References: https://codeberg.org/forgejo/forgejo/src/tag/v16.0.4/templates/swagger/v1\_json.tmpl

## FG-SIGNIN — Repository browser HTTP response
pass | assessed | applicable
Source: anonymous-http
Observed: {"/explore/repos": {"complete": true, "csp\_present": false, "frame\_policy": false, "hsts\_present": false, "html": true, "https": true, "json": false, "nosniff": false, "status": 403}}
Expected: Private intent: review anonymous HTTP 200; public/unspecified: informational.
Reason: Only the named path statuses were observed. HTTP 200 may be a login page, proxy error or empty API; it does not prove data access. Unknown responses remain incomplete even alongside a warning.
Action:
References: https://codeberg.org/forgejo/forgejo/src/tag/v16.0.4/templates/swagger/v1\_json.tmpl

## FG-VER — Product and version provenance
info | assessed | applicable
Source: operator-declared
Observed: {"declared\_product": "forgejo", "declared\_version": null, "declared\_version\_marker": null, "normalized\_version": "15.0.8", "observed\_product\_marker": null, "observed\_version": "15.0.8", "product\_conflict": false, "product\_source": "operator-declared", "provider\_revision": "1", "support": "qualified", "version\_conflict": false}
Expected: Declared product and consistent qualified upstream version.
Reason: Product is an operator declaration; version conflicts stop advisory inference.
Action:
References:

## FG-VER-DISCLOSE — Anonymous version disclosure
info | assessed | applicable
Source: anonymous-http
Observed: {"disclosed": true, "endpoint": "/api/v1/version"}
Expected: Review intentional version disclosure.
Reason: An explicit version value was returned anonymously; no independent penalty.
Action:
References:

## Limits
- Operator declarations are not independent product detection.
- A complete result covers selected checks only; no security certification.
- HTTP status does not prove data access or loaded configuration.
- Catalog coverage is finite; no runtime feeds or exploit tests.
