# OPSEC Publication Checklist

Use this checklist before any public release.

- Confirm all examples are synthetic.
- Confirm sample targets use `https://git.example.com` or `https://gitea.example.org`.
- Confirm no internal hostnames, customer names, local paths, or infrastructure notes are present.
- Confirm no credential material or sensitive values are present.
- Confirm reports were not copied from live scans.
- Confirm no package artifacts from third-party systems are included.
- Confirm CI uses no repository sensitive values.
- Run the OPSEC grep across source, docs, examples, and build artifacts.
- Run the marketing guardrail grep across source, docs, examples, and build artifacts.
- Review the package contents before any upload.
- Stage in a private GitHub repository first.
- Make public only after final human approval.
