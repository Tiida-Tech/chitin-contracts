// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title CrossChainVerifier
 * @notice Verifies ERC-8004 passport ownership proofs from other chains
 * @dev Works with Chitin's /api/v1/cross-chain-verify endpoint
 *
 * Flow:
 * 1. User owns ERC-8004 passport on Chain A (e.g., Polygon)
 * 2. User calls Chitin API: POST /api/v1/cross-chain-verify
 * 3. API verifies ownership on Chain A and returns signed proof
 * 4. User submits proof to this contract on Base
 * 5. Contract verifies signature and allows Chitin SBT mint
 */
contract CrossChainVerifier is Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // ═══════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════

    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event ProofVerified(
        uint256 indexed sourceAgentId,
        uint256 indexed sourceChainId,
        address indexed owner,
        bytes32 nonce
    );
    event SignatureExpiryUpdated(uint256 oldExpiry, uint256 newExpiry);

    // ═══════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════

    error InvalidSignature();
    error SignatureExpired(uint256 timestamp, uint256 currentTime);
    error NonceAlreadyUsed(bytes32 nonce);
    error InvalidVerifierAddress();
    error ZeroAddress();

    // ═══════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════

    /// @notice Address of the trusted verifier (Chitin API signer)
    address public verifier;

    /// @notice Signature expiry time in seconds (default: 5 minutes)
    uint256 public signatureExpiry = 300;

    /// @notice Used nonces to prevent replay attacks
    mapping(bytes32 => bool) public usedNonces;

    // ═══════════════════════════════════════════════════
    // Structs
    // ═══════════════════════════════════════════════════

    /**
     * @notice Cross-chain ownership proof
     * @param agentId ERC-8004 agent ID on source chain
     * @param chainId Source chain ID
     * @param owner Owner address (must match caller)
     * @param timestamp Proof generation timestamp
     * @param nonce Unique nonce for replay protection
     * @param signature Verifier's signature over the proof
     */
    struct CrossChainProof {
        uint256 agentId;
        uint256 chainId;
        address owner;
        uint256 timestamp;
        bytes32 nonce;
        bytes signature;
    }

    // ═══════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════

    /**
     * @notice Initialize the verifier contract
     * @param initialOwner Contract owner
     * @param verifier_ Trusted verifier address (Chitin API signer)
     */
    constructor(address initialOwner, address verifier_) Ownable(initialOwner) {
        if (verifier_ == address(0)) revert ZeroAddress();
        verifier = verifier_;
    }

    // ═══════════════════════════════════════════════════
    // Admin Functions
    // ═══════════════════════════════════════════════════

    /**
     * @notice Update the trusted verifier address
     * @param newVerifier New verifier address
     */
    function setVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        address oldVerifier = verifier;
        verifier = newVerifier;
        emit VerifierUpdated(oldVerifier, newVerifier);
    }

    /**
     * @notice Update signature expiry time
     * @param newExpiry New expiry time in seconds
     */
    function setSignatureExpiry(uint256 newExpiry) external onlyOwner {
        uint256 oldExpiry = signatureExpiry;
        signatureExpiry = newExpiry;
        emit SignatureExpiryUpdated(oldExpiry, newExpiry);
    }

    // ═══════════════════════════════════════════════════
    // Verification Functions
    // ═══════════════════════════════════════════════════

    /**
     * @notice Verify a cross-chain ownership proof
     * @param proof The cross-chain proof from Chitin API
     * @return True if proof is valid
     */
    function verifyProof(CrossChainProof calldata proof) public view returns (bool) {
        // Check signature expiry
        if (block.timestamp > proof.timestamp + signatureExpiry) {
            return false;
        }

        // Check nonce hasn't been used
        if (usedNonces[proof.nonce]) {
            return false;
        }

        // Recreate the message hash (must match API's createMessageHash)
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                proof.agentId,
                proof.chainId,
                proof.owner,
                proof.timestamp,
                proof.nonce
            )
        );

        // Convert to Ethereum Signed Message hash (EIP-191)
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();

        // Recover signer and verify (use tryRecover to avoid revert on invalid signature)
        (address recoveredSigner, ECDSA.RecoverError err, ) = ECDSA.tryRecover(ethSignedMessageHash, proof.signature);
        if (err != ECDSA.RecoverError.NoError) {
            return false;
        }
        return recoveredSigner == verifier;
    }

    /**
     * @notice Verify and consume a cross-chain proof
     * @dev Marks nonce as used to prevent replay
     * @param proof The cross-chain proof from Chitin API
     * @return True if proof is valid and consumed
     */
    function verifyAndConsumeProof(CrossChainProof calldata proof) external returns (bool) {
        // Check signature expiry
        if (block.timestamp > proof.timestamp + signatureExpiry) {
            revert SignatureExpired(proof.timestamp, block.timestamp);
        }

        // Check nonce hasn't been used
        if (usedNonces[proof.nonce]) {
            revert NonceAlreadyUsed(proof.nonce);
        }

        // Recreate the message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                proof.agentId,
                proof.chainId,
                proof.owner,
                proof.timestamp,
                proof.nonce
            )
        );

        // Convert to Ethereum Signed Message hash
        bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();

        // Recover signer and verify (use tryRecover to get specific error)
        (address recoveredSigner, ECDSA.RecoverError err, ) = ECDSA.tryRecover(ethSignedMessageHash, proof.signature);
        if (err != ECDSA.RecoverError.NoError || recoveredSigner != verifier) {
            revert InvalidSignature();
        }

        // Mark nonce as used
        usedNonces[proof.nonce] = true;

        emit ProofVerified(proof.agentId, proof.chainId, proof.owner, proof.nonce);

        return true;
    }

    /**
     * @notice Check if a nonce has been used
     * @param nonce The nonce to check
     * @return True if nonce has been used
     */
    function isNonceUsed(bytes32 nonce) external view returns (bool) {
        return usedNonces[nonce];
    }

    /**
     * @notice Get the message hash for a proof (for debugging/verification)
     * @param agentId ERC-8004 agent ID
     * @param chainId Source chain ID
     * @param owner Owner address
     * @param timestamp Timestamp
     * @param nonce Nonce
     * @return The message hash
     */
    function getMessageHash(
        uint256 agentId,
        uint256 chainId,
        address owner,
        uint256 timestamp,
        bytes32 nonce
    ) external pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(agentId, chainId, owner, timestamp, nonce)
        );
    }
}
