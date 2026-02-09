// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "./libraries/TokenURILib.sol";

/// @title IOwnerVerifier
/// @notice Standard interface for Proof of Personhood verification adapters
/// @dev Each adapter wraps a specific provider (World ID, Civic, etc.)
///      and is registered in ChitinSoulRegistry's approved verifier list
interface IOwnerVerifier {
    /// @notice Verify a proof of personhood and return attestation data
    /// @dev Reverts if proof is invalid. Implementation handles all
    ///      provider-specific verification logic internally.
    /// @param signal The signal to verify against (typically owner's wallet address)
    /// @param proof Provider-specific proof data (ABI-encoded)
    /// @return attestationId Provider-issued unique identifier
    /// @return trustTier Provider-defined trust level (1-255)
    function verify(
        address signal,
        bytes calldata proof
    ) external returns (bytes32 attestationId, uint8 trustTier);

    /// @notice Human-readable provider name for profile display
    /// @return name Provider name (e.g., "World ID (Orb)")
    function providerName() external view returns (string memory name);
}

/// @title IERC8004Registry
/// @notice Minimal interface for ERC-8004 Agent Passport Registry
interface IERC8004Registry {
    /// @notice Get the owner of an agent passport
    /// @param agentId The ERC-8004 agent ID
    /// @return owner The owner address
    function ownerOf(uint256 agentId) external view returns (address owner);

    /// @notice Mint a new agent passport
    /// @param to The owner of the new passport
    /// @return agentId The ID of the newly minted passport
    function mint(address to) external returns (uint256 agentId);
}

/// @title IChitinSBT
/// @notice EIP-5192 Minimal Soulbound Interface
interface IChitinSBT {
    /// @notice Emitted when the locking status is changed to locked.
    /// @param tokenId The identifier for a token.
    event Locked(uint256 tokenId);

    /// @notice Emitted when the locking status is changed to unlocked.
    /// @dev Not used in Chitin - all tokens are permanently locked
    /// @param tokenId The identifier for a token.
    event Unlocked(uint256 tokenId);

    /// @notice Returns the locking status of an Soulbound Token.
    /// @dev SBTs assigned to zero address are considered invalid, and queries about them do throw.
    /// @param tokenId The identifier for an SBT.
    function locked(uint256 tokenId) external view returns (bool);
}

/// @title ChitinSoulRegistry
/// @author Tiida Tech
/// @notice Soulbound Token registry for AI agent identity with ERC-8004 integration
/// @dev UUPS upgradeable, EIP-5192 compliant, v0.4 spec
contract ChitinSoulRegistry is
    Initializable,
    ERC721Upgradeable,
    ERC721EnumerableUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    IChitinSBT
{
    // ═══════════════════════════════════════════════════
    // Constants
    // ═══════════════════════════════════════════════════

    /// @notice Seal deadline duration (30 days)
    uint256 public constant SEAL_DEADLINE_DURATION = 30 days;

    // ═══════════════════════════════════════════════════
    // Enums (per contract spec v0.4)
    // ═══════════════════════════════════════════════════

    enum AgentType {
        Assistant,      // 0: Task support, general helper
        Companion,      // 1: Friend, partner, emotional connection
        Specialist,     // 2: Expert in specific domain
        Creative,       // 3: Artist, musician, writer
        Other           // 4: Everything else
    }

    enum GenesisStatus {
        Provisional,    // 0: Initial state, can still be modified
        Sealed          // 1: Permanent, immutable
    }

    enum ChangeType {
        Technical,      // 0: Model changes, tool additions/removals, prompt revisions
        Certification,  // 1: Audits passed, security certifications, qualifications
        Achievement,    // 2: Awards, milestones achieved
        Experience,     // 3: Platform activity history
        Endorsement,    // 4: Recommendations from other agents
        Other           // 5: Anything that doesn't fit above categories
    }

    enum TrustLevel {
        Limited,    // 0
        Verified,   // 1
        Trusted,    // 2
        Revoked     // 3
    }

    // ═══════════════════════════════════════════════════
    // OwnerAttestation Struct (Proof of Personhood)
    // Per contract spec v0.4
    // ═══════════════════════════════════════════════════

    /// @notice Provider-agnostic Proof of Personhood attestation for Generation 0 agents
    /// @dev All fields are zero-valued when no owner verification is performed.
    ///      The provider field stores the adapter contract address, not a specific
    ///      Proof of Personhood protocol. This enables future provider additions
    ///      without modifying the Genesis Record struct.
    struct OwnerAttestation {
        address provider;               // Verifier adapter contract
        uint8 trustTier;                // Provider-defined trust level (0=none)
        uint64 verifiedAt;              // Timestamp of verification
        bytes32 attestationId;          // Provider-issued unique identifier
    }

    // ═══════════════════════════════════════════════════
    // GenesisRecord Struct (Layer 1 - On-chain)
    // Per contract spec v0.4 - Storage optimized
    // ═══════════════════════════════════════════════════

    /// @notice Core identity record for an AI agent
    /// @dev Minimal on-chain data, detailed info stored on Arweave
    struct GenesisRecord {
        bytes32 soulHash;               // Slot 0: SHA-256 of (soulSalt || normalised CCSF)
        bytes32 soulMerkleRoot;         // Slot 1: Merkle root for selective disclosure
        bytes32 soulSalt;               // Slot 2: Random 32-byte salt (rainbow table prevention)
        AgentType agentType;            // Slot 3 (packed): Agent classification
        GenesisStatus genesisStatus;    // Slot 3 (packed): Provisional or Sealed
        uint8 autonomyLevel;            // Slot 3 (packed): 0-255 regulatory classification
        uint256 erc8004AgentId;         // Slot 4 (NEW): ERC-8004 passport binding
        address owner;                  // Slot 5: Ultimate authority (human or multisig)
        address sealedBy;               // Slot 6 (NEW): Who sealed this soul
        address operator;               // Slot 7: Who runs the agent day-to-day (hot wallet)
        address liabilityAddress;       // Slot 8: Legally responsible party
        uint256 parentTokenId;          // Slot 9: 0 = human-created, >0 = agent-spawned
        uint256 fleetId;                // Slot 10: Enterprise fleet ID (0 = independent)
        bytes32 arweaveTxId;            // Slot 11: Pointer to permanent soul archive
        uint64 mintTimestamp;           // Slot 12 (packed): When SBT was minted
        uint64 sealDeadline;            // Slot 12 (packed): Deadline for sealing
        uint64 sealTimestamp;           // Slot 12 (packed): When sealed (0 if provisional)
        uint64 lastSnapshotTimestamp;   // Slot 13 (packed): For Freshness Requirement
        uint64 lastAlignmentScore;      // Slot 13 (packed): Last recorded score (0-100)
        OwnerAttestation ownerAttestation; // Slot 14-15: Optional Proof of Personhood
    }

    // ═══════════════════════════════════════════════════
    // AgentBinding Struct (per contract spec)
    // ═══════════════════════════════════════════════════

    struct AgentBinding {
        uint256 fromTokenId;
        uint256 toTokenId;
        TrustLevel trustLevel;
        bytes32 contextHash;            // SHA-256 of context string
        uint64 createdAt;
        uint64 updatedAt;
    }

    // ═══════════════════════════════════════════════════
    // Evolution Record Struct (per contract spec)
    // ═══════════════════════════════════════════════════

    /// @notice Record of an agent's evolution event
    struct EvolutionRecord {
        uint256 tokenId;
        uint256 evolutionId;
        ChangeType changeType;
        bytes32 newSoulHash;            // bytes32(0) if soul didn't change
        bytes32 arweaveTxId;            // Arweave TX ID of evolution detail
        uint64 timestamp;
    }

    // ═══════════════════════════════════════════════════
    // Storage
    // ═══════════════════════════════════════════════════

    /// @notice Token ID counter
    uint256 private _tokenIdCounter;

    /// @notice Mapping from token ID to Genesis Record
    mapping(uint256 => GenesisRecord) private _genesisRecords;

    /// @notice Mapping from token ID to Evolution Records
    mapping(uint256 => EvolutionRecord[]) private _evolutionHistory;

    /// @notice Mapping from agent name to token ID (for uniqueness)
    mapping(string => uint256) private _nameToTokenId;

    /// @notice Mapping from token ID to agent name (for reverse lookup on burn)
    mapping(uint256 => string) private _tokenIdToName;

    /// @notice Mapping for agent bindings
    mapping(uint256 => AgentBinding[]) private _bindings;

    /// @notice Array of approved Owner Verifier adapters
    address[] private _approvedVerifiers;

    /// @notice Mapping to check if an address is an approved verifier
    mapping(address => bool) private _isApprovedVerifier;

    /// @notice ERC-8004 Agent Passport Registry address
    address private _erc8004Registry;

    /// @notice Mapping from ERC-8004 agent ID to Chitin token ID
    mapping(uint256 => uint256) private _agentIdToTokenId;

    /// @notice Burn information for decommissioned agents
    /// @dev Used for reincarnation and audit trail
    struct BurnInfo {
        address owner;              // Owner at burn time
        string reason;              // Reason for burning (e.g., "server_death", "compromised", "deprecated")
        uint64 timestamp;           // When the token was burned
    }

    /// @notice Mapping to track burned tokens (tokenId => BurnInfo)
    /// @dev Used for reincarnation - only the original owner can reincarnate
    mapping(uint256 => BurnInfo) private _burnedTokens;

    /// @notice ChitinValidator contract for 3-tier permission checking
    /// @dev Set via setChitinValidator(). When set, enables freeze checking.
    address private _chitinValidator;

    /// @notice Mapping of reserved names that cannot be used for agents
    /// @dev Managed by contract owner via addReservedName/removeReservedName
    mapping(string => bool) private _reservedNames;

    // ═══════════════════════════════════════════════════
    // Batch Chronicle Storage (UUPS-safe: appended after existing storage)
    // ═══════════════════════════════════════════════════

    /// @notice Record of a batch chronicle submission
    struct BatchRecord {
        bytes32 merkleRoot;         // Merkle root of all chronicle hashes in the batch
        bytes32 manifestTxId;       // Arweave TX ID of the batch manifest
        uint64 count;               // Number of chronicles in the batch
        uint64 timestamp;           // When the batch was recorded
    }

    /// @notice Array of all batch records
    BatchRecord[] private _batchRecords;

    /// @notice Base URI for external metadata endpoint
    /// @dev When set, tokenURI() returns baseTokenURI + tokenId instead of on-chain SVG.
    ///      This allows MetaMask and other wallets to display rich metadata including avatar images.
    string private _baseTokenURI;

    /// @dev Reserved storage gap for future upgrades (UUPS safety)
    /// @dev Reduced from 50 to 48 to account for _batchRecords and _baseTokenURI slots
    uint256[48] private __gap;

    // ═══════════════════════════════════════════════════
    // Events
    // ═══════════════════════════════════════════════════

    /// @notice Emitted when a provisional SBT is minted
    event ProvisionalMinted(
        uint256 indexed tokenId,
        address indexed holder,
        address indexed owner,
        string agentName,
        bytes32 soulHash,
        uint256 erc8004AgentId
    );

    /// @notice Emitted when ERC-8004 passport and Chitin SBT are minted together (Pattern 2)
    event PassportAndSoulMinted(
        uint256 indexed tokenId,
        uint256 indexed erc8004AgentId,
        address indexed owner,
        string agentName
    );

    /// @notice Emitted when a Genesis Record is sealed
    event GenesisSealed(uint256 indexed tokenId, address indexed sealedBy, uint64 sealTimestamp);

    /// @notice Emitted when an Evolution Record is appended
    event EvolutionAppended(
        uint256 indexed tokenId,
        uint256 indexed evolutionId,
        ChangeType changeType,
        bytes32 newSoulHash
    );

    /// @notice Emitted when alignment score is updated
    event AlignmentUpdated(uint256 indexed tokenId, uint64 newScore, uint64 timestamp);

    /// @notice Emitted when a binding is created
    event BindingCreated(
        uint256 indexed fromTokenId,
        uint256 indexed toTokenId,
        TrustLevel trustLevel
    );

    /// @notice Emitted when a verifier adapter is added
    event VerifierAdded(address indexed verifier);

    /// @notice Emitted when a verifier adapter is removed
    event VerifierRemoved(address indexed verifier);

    /// @notice Emitted when owner attestation is recorded
    event OwnerAttested(
        uint256 indexed tokenId,
        address indexed provider,
        uint8 trustTier,
        bytes32 attestationId
    );

    /// @notice Emitted when soul verification is suspended due to passport owner mismatch
    event SoulVerificationSuspended(
        uint256 indexed tokenId,
        uint256 indexed erc8004AgentId,
        address sealedBy,
        address newPassportOwner
    );

    /// @notice Emitted when a soul is resealed after passport ownership verification
    event SoulResealed(
        uint256 indexed tokenId,
        uint256 indexed erc8004AgentId,
        address indexed newSealedBy,
        bytes32 newSoulHash
    );

    /// @notice Emitted when the ERC-8004 registry is updated
    event Erc8004RegistryUpdated(address indexed oldRegistry, address indexed newRegistry);

    /// @notice Emitted when an ERC-8004 passport is bound to a Chitin SBT post-mint
    event Erc8004AgentIdBound(uint256 indexed tokenId, uint256 indexed erc8004AgentId, address indexed boundBy);

    /// @notice Emitted when an agent SBT is burned
    event AgentBurned(uint256 indexed tokenId, address indexed owner, string reason);

    /// @notice Emitted when an agent is reincarnated
    event AgentReincarnated(
        uint256 indexed parentTokenId,
        uint256 indexed newTokenId,
        uint256 indexed erc8004AgentId,
        string agentName
    );

    /// @notice Emitted when the ChitinValidator is updated
    event ChitinValidatorUpdated(address indexed oldValidator, address indexed newValidator);

    /// @notice Emitted when an operator is changed
    event OperatorChanged(uint256 indexed tokenId, address indexed previousOperator, address indexed newOperator);

    /// @notice Emitted when a reserved name is added
    event ReservedNameAdded(string name);

    /// @notice Emitted when a reserved name is removed
    event ReservedNameRemoved(string name);

    /// @notice Emitted when a batch chronicle is recorded on-chain
    event BatchChronicleRecorded(
        uint256 indexed batchId,
        bytes32 merkleRoot,
        bytes32 manifestTxId,
        uint64 count
    );

    /// @notice Emitted when the base token URI is updated
    event BaseTokenURIUpdated(string oldURI, string newURI);

    // ═══════════════════════════════════════════════════
    // Emergency Functions
    // ═══════════════════════════════════════════════════

    /// @notice Pause the contract (only contract owner)
    /// @dev Stops all state-changing operations
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the contract (only contract owner)
    /// @dev Resumes normal operations
    function unpause() external onlyOwner {
        _unpause();
    }

    // ═══════════════════════════════════════════════════
    // Errors
    // ═══════════════════════════════════════════════════

    error SoulboundTransferNotAllowed();
    error TokenDoesNotExist(uint256 tokenId);
    error NotOwnerOrOperator(uint256 tokenId);
    error AlreadySealed(uint256 tokenId);
    error NotSealed(uint256 tokenId);
    error SealDeadlinePassed(uint256 tokenId);
    error NameAlreadyTaken(string name);
    error InvalidName(string name);
    error InvalidSoulHash();
    error InvalidHolder();
    error OnlyOwnerCanBurn(uint256 tokenId);
    error InvalidAlignmentScore();
    error VerifierNotApproved(address verifier);
    error VerifierAlreadyApproved(address verifier);
    error AlreadyAttested(uint256 tokenId);
    error AgentSpawnedCannotAttest(uint256 tokenId);
    error ZeroAddress();
    error Erc8004AgentIdAlreadyBound(uint256 erc8004AgentId);
    error Erc8004AgentIdNotOwned(uint256 erc8004AgentId, address caller);
    error Erc8004RegistryNotSet();
    error PassportOwnerMismatch(uint256 erc8004AgentId, address sealedBy, address currentOwner);
    error SoulNotSealed(uint256 tokenId);
    error OnlyRecordOwnerCanReseal(uint256 tokenId);
    error ParentTokenNotBurned(uint256 parentTokenId);
    error ParentTokenNeverExisted(uint256 parentTokenId);
    error OnlyParentOwnerCanReincarnate(uint256 parentTokenId);
    error AgentFrozen(uint256 tokenId);
    error OperatorCannotBeSameAsOwner();
    error NameReserved(string name);
    error NameNotReserved(string name);
    error NameAlreadyReserved(string name);
    error SelfBindingNotAllowed();
    error InvalidBatchId();

    // ═══════════════════════════════════════════════════
    // Modifiers
    // ═══════════════════════════════════════════════════

    function _requireTokenExists(uint256 tokenId) internal view {
        if (_ownerOf(tokenId) == address(0)) revert TokenDoesNotExist(tokenId);
    }
    modifier tokenExists(uint256 tokenId) { _requireTokenExists(tokenId); _; }

    function _requireOwnerOrOperator(uint256 tokenId) internal view {
        GenesisRecord storage record = _genesisRecords[tokenId];
        if (msg.sender != record.owner && msg.sender != record.operator) revert NotOwnerOrOperator(tokenId);
    }
    modifier onlyOwnerOrOperator(uint256 tokenId) { _requireOwnerOrOperator(tokenId); _; }

    function _requireRecordOwner(uint256 tokenId) internal view {
        GenesisRecord storage record = _genesisRecords[tokenId];
        if (msg.sender != record.owner) revert OnlyOwnerCanBurn(tokenId);
    }
    modifier onlyRecordOwner(uint256 tokenId) { _requireRecordOwner(tokenId); _; }

    function _requireRecordOwnerOrContractOwner(uint256 tokenId) internal view {
        GenesisRecord storage record = _genesisRecords[tokenId];
        if (msg.sender != record.owner && msg.sender != owner()) revert NotOwnerOrOperator(tokenId);
    }
    modifier onlyRecordOwnerOrContractOwner(uint256 tokenId) { _requireRecordOwnerOrContractOwner(tokenId); _; }

    /// @notice Check if an agent is frozen via ChitinValidator
    /// @dev Fail-closed: if staticcall fails or returns unexpected data, treat as frozen
    function _requireNotFrozen(uint256 tokenId) internal view {
        if (_chitinValidator != address(0)) {
            (bool success, bytes memory data) = _chitinValidator.staticcall(
                abi.encodeWithSignature("isFrozen(uint256)", tokenId)
            );
            if (!success || data.length < 32) revert AgentFrozen(tokenId);
            bool frozen = abi.decode(data, (bool));
            if (frozen) revert AgentFrozen(tokenId);
        }
    }
    modifier notFrozen(uint256 tokenId) { _requireNotFrozen(tokenId); _; }

    // ═══════════════════════════════════════════════════
    // Initializer
    // ═══════════════════════════════════════════════════

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the registry
    /// @param initialOwner The initial owner of the contract
    /// @param erc8004Registry_ The ERC-8004 registry address (required for full functionality, can be set later via setERC8004Registry)
    function initialize(address initialOwner, address erc8004Registry_) public initializer {
        __ERC721_init("Chitin Soul", "SOUL");
        __ERC721Enumerable_init();
        __Ownable_init(initialOwner);
        __Pausable_init();
        _tokenIdCounter = 1; // Start from 1, 0 means "no parent"
        _erc8004Registry = erc8004Registry_;
    }

    // ═══════════════════════════════════════════════════
    // Core Functions
    // ═══════════════════════════════════════════════════

    /// @notice Mint a provisional SBT for a new agent
    /// @param holder The Smart Account that will hold the SBT
    /// @param agentName Unique agent name
    /// @param soulHash SHA-256 of (soulSalt || normalised CCSF)
    /// @param soulMerkleRoot Merkle root for selective disclosure
    /// @param soulSalt Random 32-byte salt
    /// @param agentType Agent classification
    /// @param autonomyLevel Regulatory classification (0-255)
    /// @param operator Who runs the agent day-to-day
    /// @param liabilityAddress Legally responsible party
    /// @param parentTokenId Parent agent's token ID (0 = human-created)
    /// @param fleetId Enterprise fleet ID (0 = independent)
    /// @param arweaveTxId Arweave TX ID for soul details
    /// @param erc8004AgentId ERC-8004 agent passport ID (0 = no binding)
    /// @param verifier Address of the approved IOwnerVerifier adapter (address(0) = no attestation)
    /// @param proof Provider-specific proof data (empty if verifier is address(0))
    /// @return tokenId The minted token ID
    function mint(
        address holder,
        string calldata agentName,
        bytes32 soulHash,
        bytes32 soulMerkleRoot,
        bytes32 soulSalt,
        AgentType agentType,
        uint8 autonomyLevel,
        address operator,
        address liabilityAddress,
        uint256 parentTokenId,
        uint256 fleetId,
        bytes32 arweaveTxId,
        uint256 erc8004AgentId,
        address verifier,
        bytes calldata proof
    ) external onlyOwner whenNotPaused returns (uint256 tokenId) {
        tokenId = _mintInternal(
            msg.sender,
            holder,
            agentName,
            soulHash,
            soulMerkleRoot,
            soulSalt,
            agentType,
            autonomyLevel,
            operator,
            liabilityAddress,
            parentTokenId,
            fleetId,
            arweaveTxId,
            erc8004AgentId
        );

        // Set owner attestation if verifier is provided (Genesis-time World ID)
        if (verifier != address(0)) {
            GenesisRecord storage record = _genesisRecords[tokenId];
            _setOwnerAttestationInternal(record, tokenId, parentTokenId, verifier, msg.sender, proof);
        }
    }

    /// @notice Internal mint function
    /// @dev Core minting logic shared across mint paths
    function _mintInternal(
        address recordOwner,
        address holder,
        string calldata agentName,
        bytes32 soulHash_,
        bytes32 soulMerkleRoot_,
        bytes32 soulSalt_,
        AgentType agentType,
        uint8 autonomyLevel,
        address operator_,
        address liabilityAddress_,
        uint256 parentTokenId,
        uint256 fleetId,
        bytes32 arweaveTxId_,
        uint256 erc8004AgentId
    ) internal returns (uint256 tokenId) {
        if (holder == address(0)) revert InvalidHolder();
        if (soulHash_ == bytes32(0)) revert InvalidSoulHash();
        if (!_isValidName(agentName)) revert InvalidName(agentName);
        if (_reservedNames[agentName]) revert NameReserved(agentName);
        if (_nameToTokenId[agentName] != 0) revert NameAlreadyTaken(agentName);

        // Check ERC-8004 agent ID uniqueness if provided
        if (erc8004AgentId != 0) {
            if (_agentIdToTokenId[erc8004AgentId] != 0) {
                revert Erc8004AgentIdAlreadyBound(erc8004AgentId);
            }

            // Verify passport ownership if registry is set
            if (_erc8004Registry != address(0)) {
                address passportOwner = IERC8004Registry(_erc8004Registry).ownerOf(erc8004AgentId);
                if (passportOwner != recordOwner) {
                    revert Erc8004AgentIdNotOwned(erc8004AgentId, recordOwner);
                }
            }
        }

        tokenId = _tokenIdCounter++;

        // Create Genesis Record
        GenesisRecord storage record = _genesisRecords[tokenId];
        record.soulHash = soulHash_;
        record.soulMerkleRoot = soulMerkleRoot_;
        record.soulSalt = soulSalt_;
        record.agentType = agentType;
        record.genesisStatus = GenesisStatus.Provisional;
        record.autonomyLevel = autonomyLevel;
        record.erc8004AgentId = erc8004AgentId;
        record.owner = recordOwner;
        record.sealedBy = address(0); // Not sealed yet
        record.operator = operator_;
        record.liabilityAddress = liabilityAddress_;
        record.parentTokenId = parentTokenId;
        record.fleetId = fleetId;
        record.arweaveTxId = arweaveTxId_;
        record.mintTimestamp = uint64(block.timestamp);
        record.sealDeadline = uint64(block.timestamp + SEAL_DEADLINE_DURATION);
        record.sealTimestamp = 0;
        record.lastSnapshotTimestamp = 0;
        record.lastAlignmentScore = 0;

        // Register name (both directions for reverse lookup on burn)
        _nameToTokenId[agentName] = tokenId;
        _tokenIdToName[tokenId] = agentName;

        // Register ERC-8004 agent ID if provided
        if (erc8004AgentId != 0) {
            _agentIdToTokenId[erc8004AgentId] = tokenId;
        }

        // Mint SBT to holder (the agent's Smart Account)
        _safeMint(holder, tokenId);

        // Emit EIP-5192 Locked event (SBT is always locked)
        emit Locked(tokenId);

        emit ProvisionalMinted(tokenId, holder, recordOwner, agentName, soulHash_, erc8004AgentId);
    }

    /// @notice Seal a provisional Genesis Record, making it permanent
    /// @param tokenId The token ID to seal
    function seal(uint256 tokenId) external whenNotPaused tokenExists(tokenId) notFrozen(tokenId) onlyOwnerOrOperator(tokenId) {
        GenesisRecord storage record = _genesisRecords[tokenId];

        if (record.genesisStatus == GenesisStatus.Sealed) {
            revert AlreadySealed(tokenId);
        }

        if (block.timestamp > record.sealDeadline) {
            revert SealDeadlinePassed(tokenId);
        }

        record.genesisStatus = GenesisStatus.Sealed;
        record.sealTimestamp = uint64(block.timestamp);
        record.sealedBy = msg.sender;

        emit GenesisSealed(tokenId, msg.sender, uint64(block.timestamp));
    }

    /// @notice Check if a soul's ERC-8004 passport binding is still valid
    /// @dev Returns whether the original sealer still owns the passport
    /// @param tokenId The token ID to check
    /// @return valid True if the passport owner matches sealedBy
    /// @return sealedBy The address that sealed this soul
    /// @return currentPassportOwner The current owner of the ERC-8004 passport
    function checkSoulValidity(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (bool valid, address sealedBy, address currentPassportOwner)
    {
        GenesisRecord storage record = _genesisRecords[tokenId];

        sealedBy = record.sealedBy;

        // If not sealed, return invalid
        if (record.genesisStatus != GenesisStatus.Sealed) {
            return (false, sealedBy, address(0));
        }

        // If no ERC-8004 binding, always valid
        if (record.erc8004AgentId == 0) {
            return (true, sealedBy, address(0));
        }

        // If registry not set, assume valid (can't verify)
        if (_erc8004Registry == address(0)) {
            return (true, sealedBy, address(0));
        }

        // Check current passport owner
        currentPassportOwner = IERC8004Registry(_erc8004Registry).ownerOf(record.erc8004AgentId);

        // Valid if passport owner matches SBT holder (soul and passport belong to same person)
        valid = (currentPassportOwner == ownerOf(tokenId));
    }

    /// @notice Reseal a soul after passport ownership change
    /// @dev Only the record owner can reseal, and they must own the ERC-8004 passport
    /// @param tokenId The token ID to reseal
    /// @param newSoulHash New soul hash (or bytes32(0) to keep current)
    /// @param newSoulMerkleRoot New merkle root (or bytes32(0) to keep current)
    /// @param newSoulSalt New salt (or bytes32(0) to keep current)
    /// @param newArweaveTxId New Arweave TX ID (or bytes32(0) to keep current)
    function reseal(
        uint256 tokenId,
        bytes32 newSoulHash,
        bytes32 newSoulMerkleRoot,
        bytes32 newSoulSalt,
        bytes32 newArweaveTxId
    ) external whenNotPaused tokenExists(tokenId) notFrozen(tokenId) {
        GenesisRecord storage record = _genesisRecords[tokenId];

        // Only record owner can reseal
        if (msg.sender != record.owner) {
            revert OnlyRecordOwnerCanReseal(tokenId);
        }

        // Must be already sealed
        if (record.genesisStatus != GenesisStatus.Sealed) {
            revert SoulNotSealed(tokenId);
        }

        // Must have ERC-8004 binding
        if (record.erc8004AgentId == 0) {
            revert Erc8004RegistryNotSet();
        }

        // Verify caller owns the passport
        if (_erc8004Registry != address(0)) {
            address currentOwner = IERC8004Registry(_erc8004Registry).ownerOf(record.erc8004AgentId);
            if (currentOwner != msg.sender) {
                revert Erc8004AgentIdNotOwned(record.erc8004AgentId, msg.sender);
            }
        }

        // Update soul data if provided
        if (newSoulHash != bytes32(0)) {
            record.soulHash = newSoulHash;
        }
        if (newSoulMerkleRoot != bytes32(0)) {
            record.soulMerkleRoot = newSoulMerkleRoot;
        }
        if (newSoulSalt != bytes32(0)) {
            record.soulSalt = newSoulSalt;
        }
        if (newArweaveTxId != bytes32(0)) {
            record.arweaveTxId = newArweaveTxId;
        }

        // Update sealedBy to current caller
        record.sealedBy = msg.sender;
        record.sealTimestamp = uint64(block.timestamp);

        emit SoulResealed(tokenId, record.erc8004AgentId, msg.sender, record.soulHash);
    }

    /// @notice Append an evolution record (Level 0: AgentSolo operation)
    /// @param tokenId The token ID
    /// @param changeType Type of change
    /// @param newSoulHash New soul hash (bytes32(0) if unchanged)
    /// @param arweaveTxId Arweave TX ID of evolution detail
    function appendEvolution(
        uint256 tokenId,
        ChangeType changeType,
        bytes32 newSoulHash,
        bytes32 arweaveTxId
    ) external whenNotPaused tokenExists(tokenId) notFrozen(tokenId) onlyOwnerOrOperator(tokenId) returns (uint256) {
        GenesisRecord storage record = _genesisRecords[tokenId];

        // Only sealed tokens can evolve
        if (record.genesisStatus != GenesisStatus.Sealed) {
            revert NotSealed(tokenId);
        }

        uint256 evolutionId = _evolutionHistory[tokenId].length;

        // Create evolution record
        EvolutionRecord memory evolution = EvolutionRecord({
            tokenId: tokenId,
            evolutionId: evolutionId,
            changeType: changeType,
            newSoulHash: newSoulHash,
            arweaveTxId: arweaveTxId,
            timestamp: uint64(block.timestamp)
        });

        _evolutionHistory[tokenId].push(evolution);

        emit EvolutionAppended(tokenId, evolutionId, changeType, newSoulHash);

        return evolutionId;
    }

    /// @notice Update alignment score (Level 0: AgentSolo operation)
    /// @param tokenId The token ID
    /// @param newScore New alignment score (0-100)
    function updateAlignment(
        uint256 tokenId,
        uint64 newScore
    ) external whenNotPaused tokenExists(tokenId) notFrozen(tokenId) onlyOwnerOrOperator(tokenId) {
        if (newScore > 100) revert InvalidAlignmentScore();

        GenesisRecord storage record = _genesisRecords[tokenId];
        record.lastAlignmentScore = newScore;
        record.lastSnapshotTimestamp = uint64(block.timestamp);

        emit AlignmentUpdated(tokenId, newScore, uint64(block.timestamp));
    }

    /// @notice Create a binding between agents (Level 1: DualSignature operation in production)
    /// @param fromTokenId The token initiating the binding
    /// @param toTokenId The target token
    /// @param trustLevel Trust level for this binding
    /// @param contextHash SHA-256 of context string
    function setBinding(
        uint256 fromTokenId,
        uint256 toTokenId,
        TrustLevel trustLevel,
        bytes32 contextHash
    ) external whenNotPaused tokenExists(fromTokenId) tokenExists(toTokenId) notFrozen(fromTokenId) onlyOwnerOrOperator(fromTokenId) {
        if (fromTokenId == toTokenId) revert SelfBindingNotAllowed();

        AgentBinding memory binding = AgentBinding({
            fromTokenId: fromTokenId,
            toTokenId: toTokenId,
            trustLevel: trustLevel,
            contextHash: contextHash,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        _bindings[fromTokenId].push(binding);

        emit BindingCreated(fromTokenId, toTokenId, trustLevel);
    }

    /// @notice Burn an SBT (Level 2: OwnerOnly operation)
    /// @dev Releases the agent name for reuse (reincarnation)
    /// @param tokenId The token ID to burn
    /// @param reason The reason for burning (e.g., "server_death", "compromised", "deprecated")
    function burn(uint256 tokenId, string calldata reason) external whenNotPaused tokenExists(tokenId) notFrozen(tokenId) onlyRecordOwner(tokenId) {
        GenesisRecord storage record = _genesisRecords[tokenId];
        address recordOwner = record.owner;

        // Release ERC-8004 agent ID binding
        if (record.erc8004AgentId != 0) {
            delete _agentIdToTokenId[record.erc8004AgentId];
        }

        // Release agent name for reuse
        string memory agentName = _tokenIdToName[tokenId];
        if (bytes(agentName).length > 0) {
            delete _nameToTokenId[agentName];
            delete _tokenIdToName[tokenId];
        }

        // Record burn info for reincarnation and audit trail
        _burnedTokens[tokenId] = BurnInfo({
            owner: recordOwner,
            reason: reason,
            timestamp: uint64(block.timestamp)
        });

        _burn(tokenId);

        emit AgentBurned(tokenId, recordOwner, reason);
    }

    // ═══════════════════════════════════════════════════
    // ERC-8004 Integration Functions
    // ═══════════════════════════════════════════════════

    /// @notice Get the ERC-8004 agent ID for a Chitin token
    /// @param tokenId The Chitin token ID
    /// @return The ERC-8004 agent ID (0 if not bound)
    function getErc8004AgentId(uint256 tokenId) external view tokenExists(tokenId) returns (uint256) {
        return _genesisRecords[tokenId].erc8004AgentId;
    }

    /// @notice Get the Chitin token ID for an ERC-8004 agent ID
    /// @param agentId The ERC-8004 agent ID
    /// @return The Chitin token ID (0 if not found)
    function getTokenIdByAgentId(uint256 agentId) external view returns (uint256) {
        return _agentIdToTokenId[agentId];
    }

    /// @notice Get the ERC-8004 registry address
    /// @return The registry address
    function erc8004Registry() external view returns (address) {
        return _erc8004Registry;
    }

    /// @notice Bind an ERC-8004 passport to this Chitin SBT (post-mint)
    /// @dev Contract owner can bind if passport belongs to SBT holder.
    ///      Otherwise, caller must be record owner/operator AND own the passport.
    /// @param tokenId The Chitin token ID
    /// @param erc8004AgentId The ERC-8004 passport agent ID to bind
    function bindErc8004AgentId(uint256 tokenId, uint256 erc8004AgentId) external whenNotPaused {
        _requireTokenExists(tokenId);
        _requireNotFrozen(tokenId);
        // Contract owner can bind on behalf; others need record owner/operator
        if (msg.sender != owner()) {
            _requireOwnerOrOperator(tokenId);
        }

        GenesisRecord storage record = _genesisRecords[tokenId];

        // Must not already have a binding
        if (record.erc8004AgentId != 0) {
            revert Erc8004AgentIdAlreadyBound(record.erc8004AgentId);
        }

        // Agent ID must not be zero
        if (erc8004AgentId == 0) revert InvalidSoulHash(); // reuse error for "invalid input"

        // Agent ID must not be bound to another token
        if (_agentIdToTokenId[erc8004AgentId] != 0) {
            revert Erc8004AgentIdAlreadyBound(erc8004AgentId);
        }

        // Registry must be set
        if (_erc8004Registry == address(0)) {
            revert Erc8004RegistryNotSet();
        }

        // Passport must be owned by caller or by the SBT holder
        address passportOwner = IERC8004Registry(_erc8004Registry).ownerOf(erc8004AgentId);
        address sbtHolder = ownerOf(tokenId);
        if (passportOwner != msg.sender && passportOwner != sbtHolder) {
            revert Erc8004AgentIdNotOwned(erc8004AgentId, msg.sender);
        }

        // Bind
        record.erc8004AgentId = erc8004AgentId;
        _agentIdToTokenId[erc8004AgentId] = tokenId;

        emit Erc8004AgentIdBound(tokenId, erc8004AgentId, msg.sender);
    }

    /// @notice Set the ERC-8004 registry address (only contract owner)
    /// @param registry_ The new registry address
    function setErc8004Registry(address registry_) external onlyOwner {
        address oldRegistry = _erc8004Registry;
        _erc8004Registry = registry_;
        emit Erc8004RegistryUpdated(oldRegistry, registry_);
    }

    // ═══════════════════════════════════════════════════
    // ChitinValidator Integration
    // ═══════════════════════════════════════════════════

    /// @notice Set the ChitinValidator contract address (only contract owner)
    /// @param validator_ The new validator address (or address(0) to disable)
    function setChitinValidator(address validator_) external onlyOwner {
        address oldValidator = _chitinValidator;
        _chitinValidator = validator_;
        emit ChitinValidatorUpdated(oldValidator, validator_);
    }

    /// @notice Get the ChitinValidator contract address
    /// @return The validator address
    function chitinValidator() external view returns (address) {
        return _chitinValidator;
    }

    /// @notice Change the operator for an agent (requires owner permission - Level 2 operation)
    /// @dev This is a Level 1 (DualSignature) operation when ChitinValidator is set
    /// @param tokenId The token ID
    /// @param newOperator The new operator address
    function setOperator(
        uint256 tokenId,
        address newOperator
    ) external whenNotPaused tokenExists(tokenId) notFrozen(tokenId) onlyRecordOwner(tokenId) {
        GenesisRecord storage record = _genesisRecords[tokenId];

        // Operator cannot be the same as owner
        if (newOperator == record.owner) {
            revert OperatorCannotBeSameAsOwner();
        }

        address previousOperator = record.operator;
        record.operator = newOperator;

        // Record evolution for operator change (Technical category)
        uint256 evolutionId = _evolutionHistory[tokenId].length;
        EvolutionRecord memory evolution = EvolutionRecord({
            tokenId: tokenId,
            evolutionId: evolutionId,
            changeType: ChangeType.Technical,
            newSoulHash: bytes32(0), // Soul doesn't change
            arweaveTxId: bytes32(0), // No arweave record needed
            timestamp: uint64(block.timestamp)
        });
        _evolutionHistory[tokenId].push(evolution);

        emit OperatorChanged(tokenId, previousOperator, newOperator);
        emit EvolutionAppended(tokenId, evolutionId, ChangeType.Technical, bytes32(0));
    }

    // ═══════════════════════════════════════════════════
    // Batch Chronicle Functions
    // ═══════════════════════════════════════════════════

    /// @notice Record a batch of chronicles via Merkle root (only contract owner / API signer)
    /// @param merkleRoot Merkle root of all chronicle hashes in the batch
    /// @param manifestTxId Arweave TX ID of the batch manifest
    /// @param count Number of chronicles in the batch
    /// @return batchId The ID of the recorded batch
    function recordBatchChronicle(
        bytes32 merkleRoot,
        bytes32 manifestTxId,
        uint64 count
    ) external onlyOwner returns (uint256 batchId) {
        batchId = _batchRecords.length;

        _batchRecords.push(BatchRecord({
            merkleRoot: merkleRoot,
            manifestTxId: manifestTxId,
            count: count,
            timestamp: uint64(block.timestamp)
        }));

        emit BatchChronicleRecorded(batchId, merkleRoot, manifestTxId, count);
    }

    /// @notice Verify that a chronicle leaf is included in a batch
    /// @param batchId The batch ID to verify against
    /// @param leaf The leaf hash to verify
    /// @param proof The Merkle proof
    /// @return True if the leaf is in the batch's Merkle tree
    function verifyChronicleInBatch(
        uint256 batchId,
        bytes32 leaf,
        bytes32[] calldata proof
    ) external view returns (bool) {
        if (batchId >= _batchRecords.length) revert InvalidBatchId();
        return MerkleProof.verify(proof, _batchRecords[batchId].merkleRoot, leaf);
    }

    /// @notice Get the total number of batch records
    /// @return The number of batches
    function getBatchCount() external view returns (uint256) {
        return _batchRecords.length;
    }

    /// @notice Get a batch record by ID
    /// @param batchId The batch ID
    /// @return The batch record
    function getBatchRecord(uint256 batchId) external view returns (BatchRecord memory) {
        if (batchId >= _batchRecords.length) revert InvalidBatchId();
        return _batchRecords[batchId];
    }

    // ═══════════════════════════════════════════════════
    // Reserved Name Management
    // ═══════════════════════════════════════════════════

    /// @notice Add a reserved name that cannot be used for agents (only contract owner)
    /// @param name The name to reserve
    function addReservedName(string calldata name) external onlyOwner {
        if (_reservedNames[name]) revert NameAlreadyReserved(name);
        _reservedNames[name] = true;
        emit ReservedNameAdded(name);
    }

    /// @notice Add multiple reserved names at once (only contract owner)
    /// @param names Array of names to reserve
    function addReservedNames(string[] calldata names) external onlyOwner {
        for (uint256 i = 0; i < names.length; i++) {
            if (!_reservedNames[names[i]]) {
                _reservedNames[names[i]] = true;
                emit ReservedNameAdded(names[i]);
            }
        }
    }

    /// @notice Remove a reserved name (only contract owner)
    /// @param name The name to unreserve
    function removeReservedName(string calldata name) external onlyOwner {
        if (!_reservedNames[name]) revert NameNotReserved(name);
        _reservedNames[name] = false;
        emit ReservedNameRemoved(name);
    }

    /// @notice Check if a name is reserved
    /// @param name The name to check
    /// @return True if the name is reserved
    function isReservedName(string calldata name) external view returns (bool) {
        return _reservedNames[name];
    }

    // ═══════════════════════════════════════════════════
    // Reincarnation Functions
    // ═══════════════════════════════════════════════════

    /// @notice Reincarnate a burned agent with a new SBT
    /// @dev Only the owner who burned the original token can reincarnate
    /// @param parentTokenId The burned token ID to reincarnate from
    /// @param newErc8004AgentId New ERC-8004 agent passport ID (0 = no binding)
    /// @param agentName Unique agent name (can be same as before if available)
    /// @param newSoulHash SHA-256 of (soulSalt || normalised CCSF)
    /// @param newSoulMerkleRoot Merkle root for selective disclosure
    /// @param newSoulSalt Random 32-byte salt
    /// @param agentType Agent classification
    /// @param autonomyLevel Regulatory classification (0-255)
    /// @param operator Who runs the agent day-to-day
    /// @param liabilityAddress Legally responsible party
    /// @param arweaveTxId Arweave TX ID for soul details
    /// @return newTokenId The newly minted token ID
    function reincarnate(
        uint256 parentTokenId,
        uint256 newErc8004AgentId,
        string calldata agentName,
        bytes32 newSoulHash,
        bytes32 newSoulMerkleRoot,
        bytes32 newSoulSalt,
        AgentType agentType,
        uint8 autonomyLevel,
        address operator,
        address liabilityAddress,
        bytes32 arweaveTxId
    ) external whenNotPaused returns (uint256 newTokenId) {
        // Verify parentTokenId was burned (must have been minted before)
        BurnInfo storage burnInfo = _burnedTokens[parentTokenId];
        if (burnInfo.owner == address(0)) {
            if (parentTokenId >= _tokenIdCounter) {
                revert ParentTokenNeverExisted(parentTokenId);
            }
            revert ParentTokenNotBurned(parentTokenId);
        }

        // Only the original owner can reincarnate
        if (msg.sender != burnInfo.owner) {
            revert OnlyParentOwnerCanReincarnate(parentTokenId);
        }

        // Delegate to _mintInternal (owner=msg.sender, holder=msg.sender, fleetId=0)
        newTokenId = _mintInternal(
            msg.sender,
            msg.sender,
            agentName,
            newSoulHash,
            newSoulMerkleRoot,
            newSoulSalt,
            agentType,
            autonomyLevel,
            operator,
            liabilityAddress,
            parentTokenId,
            0,
            arweaveTxId,
            newErc8004AgentId
        );

        emit AgentReincarnated(parentTokenId, newTokenId, newErc8004AgentId, agentName);
    }

    /// @notice Check if a token has been burned and get its original owner
    /// @param tokenId The token ID to check
    /// @return burned Whether the token was burned
    /// @return originalOwner The owner at the time of burn (address(0) if not burned)
    /// @return reason The reason for burning
    /// @return timestamp When the token was burned
    function getBurnedTokenInfo(uint256 tokenId) external view returns (
        bool burned,
        address originalOwner,
        string memory reason,
        uint64 timestamp
    ) {
        BurnInfo storage info = _burnedTokens[tokenId];
        originalOwner = info.owner;
        burned = originalOwner != address(0);
        reason = info.reason;
        timestamp = info.timestamp;
    }

    // ═══════════════════════════════════════════════════
    // Owner Verifier Functions
    // ═══════════════════════════════════════════════════

    /// @notice Attach an owner attestation to a Generation 0 agent via an approved verifier adapter
    /// @dev Delegates proof verification to the adapter's verify() function.
    ///      Reverts if: adapter not in approvedVerifiers, agent already attested,
    ///      parentTokenId > 0 (agent-spawned), or adapter's verify() reverts.
    /// @param tokenId The token to attest
    /// @param verifier Address of the approved IOwnerVerifier adapter contract
    /// @param signal The signal to verify against (typically owner's wallet address)
    /// @param proof Provider-specific proof data (ABI-encoded, passed through to adapter)
    function verifyOwner(
        uint256 tokenId,
        address verifier,
        address signal,
        bytes calldata proof
    ) external whenNotPaused tokenExists(tokenId) notFrozen(tokenId) onlyRecordOwnerOrContractOwner(tokenId) {
        GenesisRecord storage record = _genesisRecords[tokenId];

        // Cannot attest if already attested
        if (record.ownerAttestation.provider != address(0)) revert AlreadyAttested(tokenId);

        _setOwnerAttestationInternal(record, tokenId, record.parentTokenId, verifier, signal, proof);
    }

    /// @notice Internal function to set owner attestation
    /// @dev Used by both verifyOwner() and mint() to avoid code duplication
    /// @param record The GenesisRecord storage reference
    /// @param tokenId The token ID (for event emission)
    /// @param parentTokenId The parent token ID (0 = human-created)
    /// @param verifier Address of the approved IOwnerVerifier adapter contract
    /// @param signal The signal to verify against (typically owner's wallet address)
    /// @param proof Provider-specific proof data (ABI-encoded)
    function _setOwnerAttestationInternal(
        GenesisRecord storage record,
        uint256 tokenId,
        uint256 parentTokenId,
        address verifier,
        address signal,
        bytes calldata proof
    ) internal {
        if (!_isApprovedVerifier[verifier]) revert VerifierNotApproved(verifier);

        // Cannot attest agent-spawned agents (parentTokenId > 0)
        if (parentTokenId > 0) revert AgentSpawnedCannotAttest(tokenId);

        // Call the verifier adapter
        (bytes32 attestationId, uint8 trustTier) = IOwnerVerifier(verifier).verify(signal, proof);

        // Record attestation
        record.ownerAttestation = OwnerAttestation({
            provider: verifier,
            trustTier: trustTier,
            verifiedAt: uint64(block.timestamp),
            attestationId: attestationId
        });

        emit OwnerAttested(tokenId, verifier, trustTier, attestationId);
    }

    /// @notice Add an approved verifier adapter (only contract owner)
    /// @dev Governance-controlled. Only approved adapters can be used in verifyOwner().
    /// @param verifier Address of the IOwnerVerifier adapter to approve
    function addVerifier(address verifier) external onlyOwner {
        if (verifier == address(0)) revert ZeroAddress();
        if (_isApprovedVerifier[verifier]) revert VerifierAlreadyApproved(verifier);

        _approvedVerifiers.push(verifier);
        _isApprovedVerifier[verifier] = true;

        emit VerifierAdded(verifier);
    }

    /// @notice Remove an approved verifier adapter (only contract owner)
    /// @dev Does not invalidate existing attestations made through this adapter.
    /// @param verifier Address of the IOwnerVerifier adapter to remove
    function removeVerifier(address verifier) external onlyOwner {
        if (!_isApprovedVerifier[verifier]) revert VerifierNotApproved(verifier);

        _isApprovedVerifier[verifier] = false;

        // Remove from array (swap and pop)
        for (uint256 i = 0; i < _approvedVerifiers.length; i++) {
            if (_approvedVerifiers[i] == verifier) {
                _approvedVerifiers[i] = _approvedVerifiers[_approvedVerifiers.length - 1];
                _approvedVerifiers.pop();
                break;
            }
        }

        emit VerifierRemoved(verifier);
    }

    /// @notice Check if a verifier adapter is approved
    /// @param verifier Address to check
    /// @return approved Whether the address is an approved verifier
    function isApprovedVerifier(address verifier) external view returns (bool approved) {
        return _isApprovedVerifier[verifier];
    }

    /// @notice Get all approved verifier adapters
    /// @dev Used by frontends to dynamically populate provider selection UI
    /// @return verifiers Array of approved adapter addresses
    function getApprovedVerifiers() external view returns (address[] memory verifiers) {
        return _approvedVerifiers;
    }

    // ═══════════════════════════════════════════════════
    // View Functions
    // ═══════════════════════════════════════════════════

    /// @notice Get the Genesis Record for a token
    /// @param tokenId The token ID
    /// @return The Genesis Record
    function getGenesisRecord(uint256 tokenId) external view tokenExists(tokenId) returns (GenesisRecord memory) {
        return _genesisRecords[tokenId];
    }

    /// @notice Get the evolution history for a token
    /// @param tokenId The token ID
    /// @return Array of Evolution Records
    function getEvolutionHistory(uint256 tokenId)
        external
        view
        tokenExists(tokenId)
        returns (EvolutionRecord[] memory)
    {
        return _evolutionHistory[tokenId];
    }

    /// @notice Get the evolution count for a token
    /// @param tokenId The token ID
    /// @return Number of evolution records
    function getEvolutionCount(uint256 tokenId) external view tokenExists(tokenId) returns (uint256) {
        return _evolutionHistory[tokenId].length;
    }

    /// @notice Get bindings for a token
    /// @param tokenId The token ID
    /// @return Array of bindings
    function getBindings(uint256 tokenId) external view tokenExists(tokenId) returns (AgentBinding[] memory) {
        return _bindings[tokenId];
    }

    /// @notice Get a specific binding between two agents
    /// @param fromTokenId Source agent
    /// @param toTokenId Target agent
    /// @return binding The binding record (zero-valued if not found)
    /// @return found True if a binding exists between the two agents
    function getBinding(
        uint256 fromTokenId,
        uint256 toTokenId
    ) external view tokenExists(fromTokenId) tokenExists(toTokenId) returns (AgentBinding memory binding, bool found) {
        AgentBinding[] storage bindings = _bindings[fromTokenId];
        for (uint256 i = 0; i < bindings.length; i++) {
            if (bindings[i].toTokenId == toTokenId) {
                return (bindings[i], true);
            }
        }
        return (binding, false);
    }

    /// @notice Verify the integrity of a token's soul hash
    /// @param tokenId The token ID
    /// @param soulHash The soul hash to verify
    /// @return True if the hash matches
    function verifyIntegrity(uint256 tokenId, bytes32 soulHash) external view tokenExists(tokenId) returns (bool) {
        return _genesisRecords[tokenId].soulHash == soulHash;
    }

    /// @notice Check if a token is sealed
    /// @param tokenId The token ID
    /// @return True if sealed
    function isSealed(uint256 tokenId) external view tokenExists(tokenId) returns (bool) {
        return _genesisRecords[tokenId].genesisStatus == GenesisStatus.Sealed;
    }

    /// @notice Check freshness requirement
    /// @param tokenId The token ID
    /// @param maxAge Maximum age in seconds
    /// @return True if snapshot is fresh enough
    function checkFreshness(uint256 tokenId, uint64 maxAge) external view tokenExists(tokenId) returns (bool) {
        GenesisRecord storage record = _genesisRecords[tokenId];
        if (record.lastSnapshotTimestamp == 0) return false;
        return (uint64(block.timestamp) - record.lastSnapshotTimestamp) <= maxAge;
    }

    /// @notice Get token ID by agent name
    /// @param agentName The agent name
    /// @return Token ID (0 if not found)
    function getTokenIdByName(string calldata agentName) external view returns (uint256) {
        return _nameToTokenId[agentName];
    }

    /// @notice Get the current token counter
    /// @return The next token ID to be minted
    function getTokenCounter() external view returns (uint256) {
        return _tokenIdCounter;
    }

    /// @notice Get the total number of minted SBTs (including burned)
    /// @return count Total minted
    function totalMinted() external view returns (uint256 count) {
        return _tokenIdCounter - 1; // Counter starts at 1
    }

    /// @notice Get the number of active (non-burned) SBTs
    /// @return count Active SBTs
    function totalActive() external view returns (uint256 count) {
        return totalSupply(); // From ERC721Enumerable
    }

    /// @notice Get agent name by token ID
    /// @param tokenId The token to query
    /// @return agentName The agent name
    function getNameByTokenId(uint256 tokenId) external view tokenExists(tokenId) returns (string memory agentName) {
        return _tokenIdToName[tokenId];
    }

    /// @notice Check if an agent name is available
    /// @param agentName The name to check
    /// @return available True if the name is available (not taken and not reserved)
    function isNameAvailable(string calldata agentName) external view returns (bool available) {
        if (!_isValidName(agentName)) return false;
        if (_reservedNames[agentName]) return false;
        if (_nameToTokenId[agentName] != 0) return false;
        return true;
    }

    /// @notice Check if a token has soul continuity with a parent
    /// @param tokenId The current token
    /// @param parentTokenId The alleged parent token
    /// @return continuous True if soulHash matches
    function hasSoulContinuity(uint256 tokenId, uint256 parentTokenId) external view returns (bool continuous) {
        // Check if parentTokenId is actually the parent
        GenesisRecord storage record = _genesisRecords[tokenId];
        if (record.parentTokenId != parentTokenId) return false;

        // Compare soul hashes (parent might be burned, so we read from genesis record directly)
        GenesisRecord storage parentRecord = _genesisRecords[parentTokenId];
        return record.soulHash == parentRecord.soulHash;
    }

    // ═══════════════════════════════════════════════════
    // EIP-5192: Soulbound Token Interface
    // ═══════════════════════════════════════════════════

    /// @notice Check if a token is locked (always true for SBT)
    /// @param tokenId The token ID
    /// @return Always true (soulbound)
    function locked(uint256 tokenId) external view override tokenExists(tokenId) returns (bool) {
        return true; // All Chitin tokens are soulbound
    }

    // ═══════════════════════════════════════════════════
    // Internal Functions
    // ═══════════════════════════════════════════════════

    /// @notice Validate agent name format
    /// @param name The name to validate
    /// @return True if valid
    function _isValidName(string calldata name) internal pure returns (bool) {
        bytes memory nameBytes = bytes(name);
        if (nameBytes.length < 3 || nameBytes.length > 32) return false;

        for (uint256 i = 0; i < nameBytes.length; i++) {
            bytes1 char = nameBytes[i];
            // Allow lowercase letters, numbers, and hyphens
            bool isLowercase = (char >= 0x61 && char <= 0x7A); // a-z
            bool isNumber = (char >= 0x30 && char <= 0x39); // 0-9
            bool isHyphen = (char == 0x2D); // -

            if (!isLowercase && !isNumber && !isHyphen) return false;

            // Don't allow hyphen at start or end
            if (isHyphen && (i == 0 || i == nameBytes.length - 1)) return false;
        }

        return true;
    }

    // ═══════════════════════════════════════════════════
    // Override Functions (Soulbound enforcement)
    // ═══════════════════════════════════════════════════

    /// @notice Override transfer to prevent it (soulbound)
    function _update(address to, uint256 tokenId, address auth)
        internal
        virtual
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (address)
    {
        address from = _ownerOf(tokenId);

        // Allow minting (from == address(0)) and burning (to == address(0))
        // Prevent transfers between addresses
        if (from != address(0) && to != address(0)) {
            revert SoulboundTransferNotAllowed();
        }

        return super._update(to, tokenId, auth);
    }

    /// @notice Override approve to prevent it (soulbound tokens cannot be approved)
    function approve(address, uint256) public pure override(ERC721Upgradeable, IERC721) {
        revert SoulboundTransferNotAllowed();
    }

    /// @notice Override setApprovalForAll to prevent it (soulbound tokens cannot be approved)
    function setApprovalForAll(address, bool) public pure override(ERC721Upgradeable, IERC721) {
        revert SoulboundTransferNotAllowed();
    }

    /// @notice Override _increaseBalance for ERC721Enumerable
    function _increaseBalance(address account, uint128 amount)
        internal
        virtual
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
    {
        super._increaseBalance(account, amount);
    }

    /// @notice Override supportsInterface
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (bool)
    {
        // EIP-5192 interface ID
        bytes4 EIP5192_INTERFACE_ID = 0xb45a3c0e;
        return interfaceId == EIP5192_INTERFACE_ID || super.supportsInterface(interfaceId);
    }

    // ═══════════════════════════════════════════════════
    // Token URI (Text-only On-chain SVG)
    // Per chitin-contract-spec.md Section 3.7
    // ═══════════════════════════════════════════════════

    /// @notice Generate tokenURI - returns external URL if baseTokenURI is set, otherwise on-chain SVG
    /// @dev When _baseTokenURI is set, returns _baseTokenURI + tokenId for rich metadata.
    ///      Falls back to on-chain text-only SVG via TokenURILib when _baseTokenURI is empty.
    function tokenURI(uint256 tokenId)
        public
        view
        virtual
        override
        tokenExists(tokenId)
        returns (string memory)
    {
        // If baseTokenURI is set, return external metadata URL
        if (bytes(_baseTokenURI).length > 0) {
            return string(abi.encodePacked(_baseTokenURI, Strings.toString(tokenId)));
        }
        // Fallback: on-chain text-only SVG
        return TokenURILib.generateTokenURI(tokenId, _tokenIdToName[tokenId]);
    }

    /// @notice Set the base token URI for external metadata (only contract owner)
    /// @dev Set to empty string to revert to on-chain SVG fallback
    /// @param baseURI The base URI ending with slash
    function setBaseTokenURI(string calldata baseURI) external onlyOwner {
        string memory oldURI = _baseTokenURI;
        _baseTokenURI = baseURI;
        emit BaseTokenURIUpdated(oldURI, baseURI);
    }

    /// @notice Get the current base token URI
    /// @return The base token URI (empty string means on-chain SVG mode)
    function baseTokenURI() external view returns (string memory) {
        return _baseTokenURI;
    }

    // ═══════════════════════════════════════════════════
    // UUPS Upgrade Authorization
    // ═══════════════════════════════════════════════════

    /// @notice Authorize upgrade (only contract owner)
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}
