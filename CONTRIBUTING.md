# Contributing to Chitin Soul Registry

Thank you for your interest in contributing to Chitin! This guide will help you get started.

## Prerequisites

- [Foundry](https://getfoundry.sh/) (forge, cast, anvil)
- Solidity 0.8.28+

## Getting Started

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/chitin-contracts.git
   cd chitin-contracts
   ```
3. **Install** dependencies:
   ```bash
   forge install
   ```
4. **Build** the project:
   ```bash
   forge build
   ```
5. **Run** the tests:
   ```bash
   forge test -vvv
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature
   ```
2. Make your changes
3. Ensure all tests pass:
   ```bash
   forge test -vvv
   ```
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add new chronicle record type
   fix: correct access control in validator
   test: add edge case tests for reincarnation
   docs: update deployment instructions
   ```
5. Push to your fork and open a **Pull Request**

## Code Style

- Follow [OpenZeppelin style conventions](https://docs.openzeppelin.com/contracts)
- Use NatSpec comments for all public/external functions
- Internal functions prefixed with `_`
- Constants in `UPPER_SNAKE_CASE`
- State variables in `camelCase` with `_` prefix for private/internal

## Testing

- All new features must include tests
- All tests must pass before a PR can be merged
- Use descriptive test names: `test_Mint_RevertsWhen_CallerNotOwner`
- Aim for high coverage on critical paths (minting, access control, upgrades)

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- Include a clear description of what changed and why
- Reference related issues if applicable
- Ensure CI passes (all tests green)

## Reporting Issues

- **Bugs**: Open a GitHub issue with reproduction steps
- **Feature requests**: Open a GitHub issue describing the use case
- **Security vulnerabilities**: See [SECURITY.md](SECURITY.md) — do NOT open public issues

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
