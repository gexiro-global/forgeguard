# VersionSec — synthetic-gitea

Schema: forgeguard.assessment.v1 | Profile: config-review | Policy: public
Score: 100 (A)
Requests: 0; incomplete: none
Skipped by profile: none

Product and version provenance: {"declared\_product": "gitea", "declared\_version": "1.27.3", "declared\_version\_marker": null, "normalized\_version": "1.27.3", "observed\_product\_marker": null, "observed\_version": null, "product\_conflict": false, "product\_source": "operator-declared", "provider\_revision": "1", "support": "qualified", "version\_conflict": false}

Catalog: {"coverage": "Not evaluated in config review"}

## FG-CONFIG-MFA — MFA declared configuration
info | assessed | applicable
Source: operator-declared
Observed: {"declared\_defaults": \[\], "values": {"security.TWO\_FACTOR\_AUTH": ""}}
Expected: Private intent: closed registration, sign-in required, forced new private repositories, MFA required for all.
Reason: In the supplied snapshot only; loaded runtime configuration is not verified. Default privacy does not establish existing repository privacy; MFA settings do not establish completed enrollment.
Action:
References: https://github.com/go-gitea/gitea/blob/v1.27.3/custom/conf/app.example.ini

## FG-CONFIG-PRIVACY — PRIVACY declared configuration
info | assessed | applicable
Source: operator-declared
Observed: {"declared\_defaults": \[\], "values": {"repository.DEFAULT\_PRIVATE": "last", "repository.FORCE\_PRIVATE": false}}
Expected: Private intent: closed registration, sign-in required, forced new private repositories, MFA required for all.
Reason: In the supplied snapshot only; loaded runtime configuration is not verified. Default privacy does not establish existing repository privacy; MFA settings do not establish completed enrollment.
Action:
References: https://github.com/go-gitea/gitea/blob/v1.27.3/custom/conf/app.example.ini

## FG-CONFIG-REGISTRATION — REGISTRATION declared configuration
info | assessed | applicable
Source: operator-declared
Observed: {"declared\_defaults": \[\], "values": {"service.DISABLE\_REGISTRATION": false, "service.REGISTER\_EMAIL\_CONFIRM": false, "service.REGISTER\_MANUAL\_CONFIRM": false}}
Expected: Private intent: closed registration, sign-in required, forced new private repositories, MFA required for all.
Reason: In the supplied snapshot only; loaded runtime configuration is not verified. Default privacy does not establish existing repository privacy; MFA settings do not establish completed enrollment.
Action:
References: https://github.com/go-gitea/gitea/blob/v1.27.3/custom/conf/app.example.ini

## FG-CONFIG-SIGNIN — SIGNIN declared configuration
info | assessed | applicable
Source: operator-declared
Observed: {"declared\_defaults": \[\], "values": {"service.REQUIRE\_SIGNIN\_VIEW": false}}
Expected: Private intent: closed registration, sign-in required, forced new private repositories, MFA required for all.
Reason: In the supplied snapshot only; loaded runtime configuration is not verified. Default privacy does not establish existing repository privacy; MFA settings do not establish completed enrollment.
Action:
References: https://github.com/go-gitea/gitea/blob/v1.27.3/custom/conf/app.example.ini

## Limits
- Operator declarations are not independent product detection.
- A complete result covers selected checks only; no security certification.
- HTTP status does not prove data access or loaded configuration.
- Catalog coverage is finite; no runtime feeds or exploit tests.
