# Security Policy

## Reporting a vulnerability

egresso is early-stage software. If you find a way to bypass enforcement, please open
a public issue titled `bypass:` — evasions are not treated as sensitive; they make the
tool better and go straight into the test suite.

For anything you believe is genuinely sensitive (e.g. a vulnerability in egresso's own
code that could harm a user running it), email the maintainer instead of filing publicly.

## Scope & guarantees

egresso reduces the blast radius of a compromised or prompt-injected agent. It is a
defense-in-depth layer, **not** a guarantee. Always pair it with least-privilege
credentials, scoped tokens, and sandboxing. Do not rely on it as your only control.
