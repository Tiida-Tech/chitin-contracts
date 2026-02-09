// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title IWorldIdRouter
/// @notice Interface for World ID Router contract
interface IWorldIdRouter {
    /// @notice Verifies a World ID proof
    /// @param root The World ID merkle tree root
    /// @param groupId The credential type (1 = Orb)
    /// @param signalHash keccak256 hash of the signal
    /// @param nullifierHash Unique identifier per user per app
    /// @param externalNullifierHash Hash of app_id and action
    /// @param proof The zero-knowledge proof [8 elements]
    function verifyProof(
        uint256 root,
        uint256 groupId,
        uint256 signalHash,
        uint256 nullifierHash,
        uint256 externalNullifierHash,
        uint256[8] calldata proof
    ) external view;
}

/// @title IOwnerVerifier
/// @notice Interface from ChitinSoulRegistry for verifier adapters
interface IOwnerVerifier {
    function verify(address signal, bytes calldata proof)
        external returns (bytes32 attestationId, uint8 trustTier);
    function providerName() external pure returns (string memory);
}

/// @title WorldIdVerifier
/// @notice Adapter contract for World ID Proof of Personhood verification
/// @dev Implements IOwnerVerifier interface for use with ChitinSoulRegistry
contract WorldIdVerifier is IOwnerVerifier, Ownable {
    // ═══════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════

    /// @notice World ID Router contract
    IWorldIdRouter public immutable worldIdRouter;

    /// @notice App ID for Chitin (hashed into externalNullifierHash)
    bytes32 public immutable appId;

    /// @notice Action string for verification (hashed into externalNullifierHash)
    /// @dev Must match frontend action string: "ownerattestation"
    string public constant ACTION = "ownerattestation";

    /// @notice Group ID for Orb verification (only Orb is supported on-chain)
    uint256 public constant GROUP_ID = 1;

    /// @notice Trust tier for Orb-verified users
    uint8 public constant TRUST_TIER_ORB = 2;

    /// @notice Mapping to prevent double-signaling (nullifierHash => used)
    mapping(uint256 => bool) public nullifierHashes;

    // ═══════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════

    error InvalidNullifier();
    error InvalidProofLength();
    error VerificationFailed();

    // ═══════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════

    event WorldIdVerified(
        address indexed signal,
        uint256 indexed nullifierHash,
        uint256 root
    );

    // ═══════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════

    /// @notice Initialize the World ID verifier
    /// @param _worldIdRouter Address of the World ID Router contract
    /// @param _appId App ID from World ID Developer Portal
    constructor(
        address _worldIdRouter,
        bytes32 _appId
    ) Ownable(msg.sender) {
        worldIdRouter = IWorldIdRouter(_worldIdRouter);
        appId = _appId;
    }

    // ═══════════════════════════════════════════════════
    // IOwnerVerifier Implementation
    // ═══════════════════════════════════════════════════

    /// @notice Verify a World ID proof and return attestation data
    /// @dev Reverts if proof is invalid or nullifier was already used
    /// @param signal The wallet address being verified
    /// @param proof ABI-encoded World ID proof data: (root, nullifierHash, proof[8])
    /// @return attestationId The nullifierHash as bytes32 (unique per user per app)
    /// @return trustTier Always TRUST_TIER_ORB (2) for World ID Orb verification
    function verify(
        address signal,
        bytes calldata proof
    ) external override returns (bytes32 attestationId, uint8 trustTier) {
        // Decode proof data
        (uint256 root, uint256 nullifierHash, uint256[8] memory proofArray) =
            abi.decode(proof, (uint256, uint256, uint256[8]));

        // Check for double-signaling
        if (nullifierHashes[nullifierHash]) revert InvalidNullifier();

        // Compute hashes
        uint256 signalHash = _hashToField(abi.encodePacked(signal));
        uint256 externalNullifierHash = _hashToField(
            abi.encodePacked(appId, ACTION)
        );

        // Verify the proof (reverts if invalid)
        try worldIdRouter.verifyProof(
            root,
            GROUP_ID,
            signalHash,
            nullifierHash,
            externalNullifierHash,
            proofArray
        ) {
            // Mark nullifier as used
            nullifierHashes[nullifierHash] = true;

            emit WorldIdVerified(signal, nullifierHash, root);

            return (bytes32(nullifierHash), TRUST_TIER_ORB);
        } catch {
            revert VerificationFailed();
        }
    }

    /// @notice Get the provider name
    /// @return Provider name string
    function providerName() external pure override returns (string memory) {
        return "World ID";
    }

    // ═══════════════════════════════════════════════════
    // Internal Functions
    // ═══════════════════════════════════════════════════

    /// @notice Hash bytes to a field element (for World ID)
    /// @dev Follows World ID's hashToField specification
    function _hashToField(bytes memory data) internal pure returns (uint256) {
        return uint256(keccak256(data)) >> 8;
    }

    // ═══════════════════════════════════════════════════
    // Admin Functions
    // ═══════════════════════════════════════════════════

    /// @notice Emergency function to reset a nullifier (owner only)
    /// @dev Should only be used in case of bugs, not to allow re-verification
    function resetNullifier(uint256 nullifierHash) external onlyOwner {
        nullifierHashes[nullifierHash] = false;
    }
}
