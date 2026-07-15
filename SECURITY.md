# Security Policy

## Reporting a Vulnerability

Do not report security vulnerabilities through a public GitHub issue.

Report potential vulnerabilities to the AMD Product Security Incident Response
Team at [psirt@amd.com](mailto:psirt@amd.com), following the instructions in the
[AMD Vulnerability Disclosure Policy](https://www.amd.com/en/resources/product-security.html).
Include the affected AXIS version or commit, impact, reproduction steps, and a
minimal proof of concept when possible.

AMD follows coordinated vulnerability disclosure. Please allow time for the
report to be acknowledged, investigated, and remediated before public
disclosure.

## Supported Versions

Security fixes are developed on the default branch and included in subsequent
releases. Users should run the latest available AXIS release. Older releases
may not receive backported fixes unless a release notice states otherwise.

## Security Model

AXIS treats a requested isolation control as mandatory. A launch must fail when
the selected backend cannot enforce that control; it must not silently weaken
the policy. Reports showing a policy bypass, sandbox escape, cross-sandbox data
exposure, credential disclosure, or fail-open behavior are security reports.
