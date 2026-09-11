# Provider development

The static registry contains GiteaProvider and ForgejoProvider implementing the
typed ForgeProvider contract. Provider code supplies product-specific config
mapping, exact qualification targets, upstream references and finite request
plans. Catalogs are separate data files, validated through Advisory models.
There is no remote plugin discovery or executable rule input.

The central client owns origin validation, authentication restrictions, budgets,
streaming, deadlines, TLS verification and response minimization. Providers do
not instantiate transports or execute shell commands.

To add or change a supported version, review version-tagged upstream configuration
and API sources, capture hashes, extend explicit catalog evidence where justified,
and run the same contract suite and real integration variants. New endpoints
require an exact central allowlist entry, a source and transport-boundary tests.
Do not infer a product from a compatible API version. Preserve raw declarations,
observations and conflicts.

Mandatory tests cover product/version conflicts, unknown syntax, catalog
boundaries/backports, partial results, policy intent, zero-network offline paths,
body/time/request limits, token/cookie isolation, schema validity, normalized
determinism and installed-package behavior. A qualification target is not a
claim of a completed test; release notes must identify actual evidence.
