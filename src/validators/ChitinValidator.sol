// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IChitinValidator
/// @notice Interface for 3-tier permission validation module
/// @dev Used by ChitinSoulRegistry for granular access control
interface IChitinValidator {
    /// @notice Permission levels for different operations
    enum PermissionLevel {
        AgentSolo,      // 0: Daily operations - agent can act alone
        DualSignature,  // 1: Elevated operations - requires owner + agent
        OwnerOnly       // 2: Critical operations - owner only
    }

    /// @notice Check if caller has permission for the specified level
    /// @param tokenId The SBT token ID
    /// @param caller The address attempting the operation
    /// @param level Required permission level
    /// @return allowed Whether the caller has permission
    function checkPermission(
        uint256 tokenId,
        address caller,
        PermissionLevel level
    ) external view returns (bool allowed);

    /// @notice Record a pending dual-signature operation
    /// @param tokenId The SBT token ID
    /// @param operationHash Hash of the pending operation
    /// @param initiator Who initiated the operation
    function initiateDualSignature(
        uint256 tokenId,
        bytes32 operationHash,
        address initiator
    ) external;

    /// @notice Confirm a pending dual-signature operation
    /// @param tokenId The SBT token ID
    /// @param operationHash Hash of the operation to confirm
    /// @param confirmer Who is confirming
    /// @return confirmed Whether both signatures are now present
    function confirmDualSignature(
        uint256 tokenId,
        bytes32 operationHash,
        address confirmer
    ) external returns (bool confirmed);

    /// @notice Cancel a pending dual-signature operation
    /// @param tokenId The SBT token ID
    /// @param operationHash Hash of the operation to cancel
    function cancelDualSignature(
        uint256 tokenId,
        bytes32 operationHash
    ) external;
}

/// @title ChitinValidator
/// @author Tiida Tech
/// @notice 3-tier permission validation module for Chitin SBT operations
/// @dev Implements agent-solo / 2-of-2 / owner-only permission model
///
/// Permission Levels:
///   Level 0 (AgentSolo): Evolution records, alignment updates, snapshots
///   Level 1 (DualSignature): Operator changes, binding creation
///   Level 2 (OwnerOnly): Burn, reincarnation, freeze
///
/// For testnet (Base Sepolia), this is a simplified implementation.
/// Production version may include timelock and more sophisticated 2-of-2 logic.
contract ChitinValidator is IChitinValidator {
    // ═══════════════════════════════════════════════════
    // Structs
    // ═══════════════════════════════════════════════════

    /// @notice Pending dual-signature operation
    struct PendingOperation {
        bytes32 operationHash;      // Hash of the operation
        address initiator;          // Who started it
        uint64 initiatedAt;         // When it was initiated
        uint64 expiresAt;           // When it expires
        bool ownerSigned;           // Has owner signed
        bool operatorSigned;        // Has operator signed
        bool executed;              // Has it been executed
    }

    /// @notice Agent permission configuration
    struct AgentPermissions {
        bool frozen;                // If true, all operations blocked
        uint64 frozenAt;            // When frozen
        address multisigPartner;    // Optional: for future multisig support
    }

    // ═══════════════════════════════════════════════════
    // Constants
    // ═══════════════════════════════════════════════════

    /// @notice How long a dual-signature request remains valid
    uint64 public constant DUAL_SIGNATURE_EXPIRY = 24 hours;

    // ═══════════════════════════════════════════════════
    // State
    // ═══════════════════════════════════════════════════

    /// @notice Reference to the ChitinSoulRegistry
    address public immutable registry;

    /// @notice Mapping from tokenId => operationHash => PendingOperation
    mapping(uint256 => mapping(bytes32 => PendingOperation)) public pendingOperations;

    /// @notice Mapping from tokenId => AgentPermissions
    mapping(uint256 => AgentPermissions) public agentPermissions;

    /// @notice Nonce for generating unique operation hashes
    mapping(uint256 => uint256) public operationNonces;

    // ═══════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════

    event DualSignatureInitiated(
        uint256 indexed tokenId,
        bytes32 indexed operationHash,
        address indexed initiator,
        uint64 expiresAt
    );

    event DualSignatureConfirmed(
        uint256 indexed tokenId,
        bytes32 indexed operationHash,
        address indexed confirmer
    );

    event DualSignatureCompleted(
        uint256 indexed tokenId,
        bytes32 indexed operationHash
    );

    event DualSignatureCancelled(
        uint256 indexed tokenId,
        bytes32 indexed operationHash
    );

    event AgentFrozen(
        uint256 indexed tokenId,
        address indexed frozenBy,
        uint64 frozenAt
    );

    event AgentUnfrozen(
        uint256 indexed tokenId,
        address indexed unfrozenBy
    );

    // ═══════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════

    error NotRegistry();
    error AgentFrozenError(uint256 tokenId);
    error InsufficientPermission(uint256 tokenId, address caller, PermissionLevel required);
    error OperationNotFound(uint256 tokenId, bytes32 operationHash);
    error OperationExpired(uint256 tokenId, bytes32 operationHash);
    error OperationAlreadyExecuted(uint256 tokenId, bytes32 operationHash);
    error AlreadySigned(uint256 tokenId, bytes32 operationHash, address signer);
    error NotOwnerOrOperator(uint256 tokenId, address caller);
    error NotOwner(uint256 tokenId, address caller);
    error AlreadyFrozen(uint256 tokenId);
    error NotFrozen(uint256 tokenId);

    // ═══════════════════════════════════════════════════
    // Constructor
    // ═══════════════════════════════════════════════════

    /// @notice Initialize the validator with reference to ChitinSoulRegistry
    /// @param _registry Address of the ChitinSoulRegistry contract
    constructor(address _registry) {
        registry = _registry;
    }

    // ═══════════════════════════════════════════════════
    // Modifiers
    // ═══════════════════════════════════════════════════

    modifier onlyRegistry() {
        if (msg.sender != registry) revert NotRegistry();
        _;
    }

    modifier notFrozen(uint256 tokenId) {
        if (agentPermissions[tokenId].frozen) revert AgentFrozenError(tokenId);
        _;
    }

    // ═══════════════════════════════════════════════════
    // Core Permission Functions
    // ═══════════════════════════════════════════════════

    /// @inheritdoc IChitinValidator
    function checkPermission(
        uint256 tokenId,
        address caller,
        PermissionLevel level
    ) external view override returns (bool allowed) {
        // Frozen agents can't do anything
        if (agentPermissions[tokenId].frozen) {
            return false;
        }

        // Get owner and operator from registry
        (address owner, address operator) = _getOwnerAndOperator(tokenId);

        if (level == PermissionLevel.AgentSolo) {
            // Level 0: Owner OR Operator can act alone
            return caller == owner || caller == operator;
        } else if (level == PermissionLevel.DualSignature) {
            // Level 1: Requires 2-of-2 signature (handled separately)
            // For direct calls, only owner can initiate
            return caller == owner || caller == operator;
        } else if (level == PermissionLevel.OwnerOnly) {
            // Level 2: Only owner
            return caller == owner;
        }

        return false;
    }

    /// @notice Check if an address is the owner of a token
    /// @param tokenId The token ID
    /// @param caller The address to check
    /// @return isOwner True if caller is the owner
    function isOwner(uint256 tokenId, address caller) external view returns (bool) {
        (address owner, ) = _getOwnerAndOperator(tokenId);
        return caller == owner;
    }

    /// @notice Check if an address is the operator of a token
    /// @param tokenId The token ID
    /// @param caller The address to check
    /// @return isOperator True if caller is the operator
    function isOperator(uint256 tokenId, address caller) external view returns (bool) {
        (, address operator) = _getOwnerAndOperator(tokenId);
        return caller == operator;
    }

    /// @notice Check if an address is owner or operator
    /// @param tokenId The token ID
    /// @param caller The address to check
    /// @return isAuthorized True if caller is owner or operator
    function isOwnerOrOperator(uint256 tokenId, address caller) external view returns (bool) {
        (address owner, address operator) = _getOwnerAndOperator(tokenId);
        return caller == owner || caller == operator;
    }

    // ═══════════════════════════════════════════════════
    // Dual Signature Functions
    // ═══════════════════════════════════════════════════

    /// @inheritdoc IChitinValidator
    function initiateDualSignature(
        uint256 tokenId,
        bytes32 operationHash,
        address initiator
    ) external override notFrozen(tokenId) {
        (address owner, address operator) = _getOwnerAndOperator(tokenId);

        // Only owner or operator can initiate
        if (initiator != owner && initiator != operator) {
            revert NotOwnerOrOperator(tokenId, initiator);
        }

        // Create pending operation
        PendingOperation storage pending = pendingOperations[tokenId][operationHash];
        pending.operationHash = operationHash;
        pending.initiator = initiator;
        pending.initiatedAt = uint64(block.timestamp);
        pending.expiresAt = uint64(block.timestamp) + DUAL_SIGNATURE_EXPIRY;
        pending.executed = false;

        // Mark initiator's signature
        if (initiator == owner) {
            pending.ownerSigned = true;
        }
        if (initiator == operator) {
            pending.operatorSigned = true;
        }

        emit DualSignatureInitiated(tokenId, operationHash, initiator, pending.expiresAt);
    }

    /// @inheritdoc IChitinValidator
    function confirmDualSignature(
        uint256 tokenId,
        bytes32 operationHash,
        address confirmer
    ) external override notFrozen(tokenId) returns (bool confirmed) {
        PendingOperation storage pending = pendingOperations[tokenId][operationHash];

        // Check operation exists
        if (pending.initiatedAt == 0) {
            revert OperationNotFound(tokenId, operationHash);
        }

        // Check not expired
        if (block.timestamp > pending.expiresAt) {
            revert OperationExpired(tokenId, operationHash);
        }

        // Check not already executed
        if (pending.executed) {
            revert OperationAlreadyExecuted(tokenId, operationHash);
        }

        (address owner, address operator) = _getOwnerAndOperator(tokenId);

        // Only owner or operator can confirm
        if (confirmer != owner && confirmer != operator) {
            revert NotOwnerOrOperator(tokenId, confirmer);
        }

        // Check not already signed by this party
        if (confirmer == owner && pending.ownerSigned) {
            revert AlreadySigned(tokenId, operationHash, confirmer);
        }
        if (confirmer == operator && pending.operatorSigned) {
            revert AlreadySigned(tokenId, operationHash, confirmer);
        }

        // Mark signature
        if (confirmer == owner) {
            pending.ownerSigned = true;
        }
        if (confirmer == operator) {
            pending.operatorSigned = true;
        }

        emit DualSignatureConfirmed(tokenId, operationHash, confirmer);

        // Check if both have signed
        if (pending.ownerSigned && pending.operatorSigned) {
            pending.executed = true;
            emit DualSignatureCompleted(tokenId, operationHash);
            return true;
        }

        return false;
    }

    /// @inheritdoc IChitinValidator
    function cancelDualSignature(
        uint256 tokenId,
        bytes32 operationHash
    ) external override {
        PendingOperation storage pending = pendingOperations[tokenId][operationHash];

        // Check operation exists
        if (pending.initiatedAt == 0) {
            revert OperationNotFound(tokenId, operationHash);
        }

        (address owner, ) = _getOwnerAndOperator(tokenId);

        // Only owner or initiator can cancel
        if (msg.sender != owner && msg.sender != pending.initiator) {
            revert NotOwner(tokenId, msg.sender);
        }

        // Delete the pending operation
        delete pendingOperations[tokenId][operationHash];

        emit DualSignatureCancelled(tokenId, operationHash);
    }

    /// @notice Check if a dual-signature operation is complete
    /// @param tokenId The token ID
    /// @param operationHash The operation hash
    /// @return complete True if both parties have signed
    function isDualSignatureComplete(
        uint256 tokenId,
        bytes32 operationHash
    ) external view returns (bool complete) {
        PendingOperation storage pending = pendingOperations[tokenId][operationHash];
        return pending.ownerSigned && pending.operatorSigned && !pending.executed;
    }

    /// @notice Get pending operation details
    /// @param tokenId The token ID
    /// @param operationHash The operation hash
    /// @return operation The pending operation details
    function getPendingOperation(
        uint256 tokenId,
        bytes32 operationHash
    ) external view returns (PendingOperation memory operation) {
        return pendingOperations[tokenId][operationHash];
    }

    /// @notice Generate a unique operation hash
    /// @param tokenId The token ID
    /// @param operationType Type of operation (e.g., "setOperator", "setBinding")
    /// @param data Additional operation data
    /// @return operationHash Unique hash for this operation
    function generateOperationHash(
        uint256 tokenId,
        string calldata operationType,
        bytes calldata data
    ) external returns (bytes32 operationHash) {
        uint256 nonce = operationNonces[tokenId]++;
        return keccak256(abi.encodePacked(tokenId, operationType, data, nonce, block.timestamp));
    }

    // ═══════════════════════════════════════════════════
    // Freeze Functions (Owner Only)
    // ═══════════════════════════════════════════════════

    /// @notice Freeze an agent (only owner can do this)
    /// @dev Frozen agents cannot perform any operations
    /// @param tokenId The token ID to freeze
    function freeze(uint256 tokenId) external {
        (address owner, ) = _getOwnerAndOperator(tokenId);
        if (msg.sender != owner) revert NotOwner(tokenId, msg.sender);

        AgentPermissions storage perms = agentPermissions[tokenId];
        if (perms.frozen) revert AlreadyFrozen(tokenId);

        perms.frozen = true;
        perms.frozenAt = uint64(block.timestamp);

        emit AgentFrozen(tokenId, msg.sender, uint64(block.timestamp));
    }

    /// @notice Unfreeze an agent (only owner can do this)
    /// @param tokenId The token ID to unfreeze
    function unfreeze(uint256 tokenId) external {
        (address owner, ) = _getOwnerAndOperator(tokenId);
        if (msg.sender != owner) revert NotOwner(tokenId, msg.sender);

        AgentPermissions storage perms = agentPermissions[tokenId];
        if (!perms.frozen) revert NotFrozen(tokenId);

        perms.frozen = false;
        perms.frozenAt = 0;

        emit AgentUnfrozen(tokenId, msg.sender);
    }

    /// @notice Check if an agent is frozen
    /// @param tokenId The token ID to check
    /// @return frozen True if the agent is frozen
    function isFrozen(uint256 tokenId) external view returns (bool) {
        return agentPermissions[tokenId].frozen;
    }

    // ═══════════════════════════════════════════════════
    // Helper Functions for Registry Integration
    // ═══════════════════════════════════════════════════

    /// @notice Validate permission for AgentSolo operations
    /// @dev Convenience function for registry to check Level 0 permissions
    /// @param tokenId The token ID
    /// @param caller The caller address
    function requireAgentSolo(uint256 tokenId, address caller) external view {
        if (agentPermissions[tokenId].frozen) {
            revert AgentFrozenError(tokenId);
        }
        (address owner, address operator) = _getOwnerAndOperator(tokenId);
        if (caller != owner && caller != operator) {
            revert InsufficientPermission(tokenId, caller, PermissionLevel.AgentSolo);
        }
    }

    /// @notice Validate permission for OwnerOnly operations
    /// @dev Convenience function for registry to check Level 2 permissions
    /// @param tokenId The token ID
    /// @param caller The caller address
    function requireOwnerOnly(uint256 tokenId, address caller) external view {
        if (agentPermissions[tokenId].frozen) {
            revert AgentFrozenError(tokenId);
        }
        (address owner, ) = _getOwnerAndOperator(tokenId);
        if (caller != owner) {
            revert InsufficientPermission(tokenId, caller, PermissionLevel.OwnerOnly);
        }
    }

    // ═══════════════════════════════════════════════════
    // Internal Functions
    // ═══════════════════════════════════════════════════

    /// @notice Get owner and operator from registry
    /// @dev Calls getGenesisRecord on the registry
    /// @param tokenId The token ID
    /// @return owner The owner address
    /// @return operator The operator address
    function _getOwnerAndOperator(uint256 tokenId) internal view returns (address owner, address operator) {
        // Call registry to get genesis record
        // Using low-level call to avoid import cycles
        (bool success, bytes memory data) = registry.staticcall(
            abi.encodeWithSignature("getGenesisRecord(uint256)", tokenId)
        );

        if (success && data.length > 0) {
            // GenesisRecord ABI encoding (each field is 32 bytes in memory):
            // Offset 0:   soulHash (bytes32)
            // Offset 32:  soulMerkleRoot (bytes32)
            // Offset 64:  soulSalt (bytes32)
            // Offset 96:  agentType (enum = uint8 padded to 32 bytes)
            // Offset 128: genesisStatus (enum = uint8 padded to 32 bytes)
            // Offset 160: autonomyLevel (uint8 padded to 32 bytes)
            // Offset 192: erc8004AgentId (uint256)
            // Offset 224: owner (address padded to 32 bytes)
            // Offset 256: sealedBy (address)
            // Offset 288: operator (address)
            // ... remaining fields

            assembly {
                // Skip the length prefix of bytes
                let ptr := add(data, 32)
                // owner is at offset 7 * 32 = 224 bytes from start of struct
                owner := mload(add(ptr, 224))
                // operator is at offset 9 * 32 = 288 bytes from start of struct
                operator := mload(add(ptr, 288))
            }
        }
    }
}
