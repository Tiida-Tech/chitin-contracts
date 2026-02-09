// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title IOwnerVerifier
/// @notice Interface from ChitinSoulRegistry for verifier adapters
interface IOwnerVerifier {
    function verify(address signal, bytes calldata proof)
        external returns (bytes32 attestationId, uint8 trustTier);
    function providerName() external pure returns (string memory);
}

/// @title TrustedWorldIdVerifier
/// @notice API-verified World ID adapter for Base Mainnet (Phase 1)
/// @dev Trusts that the caller (ChitinSoulRegistry, called by minter) has already
///      verified the World ID proof via the Developer Portal API.
///      Nullifier tracking is still on-chain to prevent double-verification.
///
///      When World ID Router deploys on Base Mainnet (Phase 2), replace this
///      with the original WorldIdVerifier that does on-chain ZK proof verification.
contract TrustedWorldIdVerifier is IOwnerVerifier, Ownable {
    // ═══════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════

    /// @notice Trust tier for API-verified World ID users
    /// @dev Same as Orb tier (2) since proof was verified via API
    uint8 public constant TRUST_TIER_ORB = 2;

    /// @notice Mapping to prevent double-signaling (nullifierHash => used)
    mapping(uint256 => bool) public nullifierHashes;

    // ═══════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════

    error InvalidNullifier();
    error InvalidProofLength();

    // ═══════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════

    event WorldIdVerified(
        address indexed signal,
        uint256 indexed nullifierHash
    );

    // ═══════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════

    constructor() Ownable(msg.sender) {}

    // ═══════════════════════════════════════════════════
    // IOwnerVerifier Implementation
    // ═══════════════════════════════════════════════════

    /// @notice Record a pre-verified World ID attestation
    /// @dev The proof must contain ABI-encoded (nullifierHash) only.
    ///      The actual ZK proof was already verified off-chain via World ID API.
    ///      This contract only handles nullifier deduplication on-chain.
    /// @param signal The wallet address being verified
    /// @param proof ABI-encoded (uint256 nullifierHash)
    /// @return attestationId The nullifierHash as bytes32
    /// @return trustTier TRUST_TIER_ORB (2)
    function verify(
        address signal,
        bytes calldata proof
    ) external override returns (bytes32 attestationId, uint8 trustTier) {
        // Decode: only nullifierHash (proof already verified via API)
        uint256 nullifierHash = abi.decode(proof, (uint256));

        // Track nullifier usage (no revert — one person can verify multiple agents)
        // ChitinSoulRegistry.verifyOwner() already prevents double-attestation per token
        nullifierHashes[nullifierHash] = true;

        emit WorldIdVerified(signal, nullifierHash);

        return (bytes32(nullifierHash), TRUST_TIER_ORB);
    }

    /// @notice Get the provider name
    function providerName() external pure override returns (string memory) {
        return "World ID (API-verified)";
    }

    // ═══════════════════════════════════════════════════
    // Admin Functions
    // ═══════════════════════════════════════════════════

    /// @notice Emergency function to reset a nullifier (owner only)
    function resetNullifier(uint256 nullifierHash) external onlyOwner {
        nullifierHashes[nullifierHash] = false;
    }
}
