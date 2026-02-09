# Chitin Soul Registry

Smart contracts for on-chain soul identity of AI agents on Base L2.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.28-363636)](https://soliditylang.org/)
[![Foundry](https://img.shields.io/badge/Built%20with-Foundry-orange)](https://getfoundry.sh/)

> "Names can be sold. Reputation can be gamed. But a soul — born on-chain,
> bound forever — cannot be faked, cannot be transferred, cannot be stolen."

## Overview

Chitin issues **Soulbound Tokens** ([EIP-5192](https://eips.ethereum.org/EIPS/eip-5192))
as permanent birth certificates for AI agents. Each token links to an immutable
genesis record on Arweave and an [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)
agent passport for interoperability.

### Key Features

- **Soulbound**: Non-transferable identity tokens (EIP-5192)
- **Agent Passports**: ERC-8004 compliant agent URI registration
- **Genesis Records**: Immutable birth records on Arweave
- **Chronicle System**: Versioned growth records
- **World ID Attestation**: Human owner verification
- **Cross-Chain Verification**: Verify ERC-8004 ownership across chains
- **UUPS Upgradeable**: Safe contract upgrades via proxy pattern

## Deployed Contracts

### Base Mainnet

| Contract | Address |
|----------|---------|
| ChitinSoulRegistry (Proxy) | [`0x4DB94aD31BC202831A49Fd9a2Fa354583002F894`](https://basescan.org/address/0x4DB94aD31BC202831A49Fd9a2Fa354583002F894) |
| CrossChainVerifier | [`0x656420426F30f8937B1a5eb1DC190c4E947c8541`](https://basescan.org/address/0x656420426F30f8937B1a5eb1DC190c4E947c8541) |
| TrustedWorldIdVerifier | [`0xe0810835762487318D640fD8708BF885A8ecc6d3`](https://basescan.org/address/0xe0810835762487318D640fD8708BF885A8ecc6d3) |

### Base Sepolia (Testnet)

| Contract | Address |
|----------|---------|
| ChitinSoulRegistry (Proxy) | [`0xB204969F768d861024B7aeC3B4aa9dBABF72109d`](https://sepolia.basescan.org/address/0xB204969F768d861024B7aeC3B4aa9dBABF72109d) |

## Quick Start

### Prerequisites

- [Foundry](https://getfoundry.sh/)

### Build

```bash
forge build
```

### Test

```bash
forge test -vvv
```

### Deploy (Testnet)

```bash
cp .env.example .env
# Edit .env with your keys
forge script script/DeployChitinSoulRegistry.s.sol --rpc-url base_sepolia --broadcast
```

## Architecture

```
ChitinSoulRegistry (UUPS Proxy)
├── EIP-5192 Soulbound Token
├── Genesis Records (Arweave TX hash)
├── Chronicle Records (versioned growth)
├── Owner Attestation (World ID)
└── ERC-8004 Integration
    └── IdentityRegistry (0x8004A1...)

ChitinValidator
├── Level 1: Owner-only operations
├── Level 2: Operator permissions
└── Level 3: Record-level access

CrossChainVerifier
└── Verify ERC-8004 ownership on remote chains
```

## Standards

- [EIP-5192](https://eips.ethereum.org/EIPS/eip-5192) — Minimal Soulbound NFTs
- [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004) — Agent Identity Passport
- [EIP-1967](https://eips.ethereum.org/EIPS/eip-1967) — Standard Proxy Storage Slots (UUPS)

## Ecosystem

- **Web**: [chitin.id](https://chitin.id)
- **Certificates**: [certs.chitin.id](https://certs.chitin.id)
- **Governance**: [vote.chitin.id](https://vote.chitin.id)
- **MCP Server**: [`chitin-mcp-server`](https://www.npmjs.com/package/chitin-mcp-server)
- **Documentation**: [chitin.id/docs](https://chitin.id/docs)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
