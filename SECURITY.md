# Security Policy

## Disclaimer

These smart contracts are **unaudited**. Use at your own risk.

While we strive for correctness and security, no formal security audit has been conducted. Users should perform their own due diligence before deploying or interacting with these contracts in production.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly through **GitHub Security Advisories**:

1. Go to the [Security tab](https://github.com/Tiida-Tech/chitin-contracts/security/advisories) of this repository
2. Click **"Report a vulnerability"**
3. Provide a detailed description of the issue

**Please do NOT open a public issue for security vulnerabilities.**

## Scope

The following are in scope for security reports:

- Smart contract vulnerabilities (reentrancy, access control bypass, integer overflow, etc.)
- Access control issues in the validator or verifier modules
- Logic errors that could lead to unauthorized token minting or state manipulation
- Proxy upgrade vulnerabilities

The following are **out of scope**:

- Gas optimization suggestions
- UI/frontend issues
- Issues in third-party dependencies (OpenZeppelin, forge-std)
- Known limitations documented in the codebase

## Response

We aim to acknowledge security reports within **48 hours** and provide a resolution timeline within **7 days**.

## Contact

For security matters only: use GitHub Security Advisories as described above.
