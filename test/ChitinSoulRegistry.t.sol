// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ChitinSoulRegistry, IOwnerVerifier, IERC8004Registry} from "../src/ChitinSoulRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice Mock Owner Verifier for testing
contract MockOwnerVerifier is IOwnerVerifier {
    function verify(
        address,
        bytes calldata
    ) external pure override returns (bytes32 attestationId, uint8 trustTier) {
        return (keccak256("mock-attestation"), 2);
    }

    function providerName() external pure override returns (string memory name) {
        return "Mock Verifier";
    }
}

/// @notice Mock ERC-8004 Registry for testing
contract MockERC8004Registry is IERC8004Registry {
    mapping(uint256 => address) private _owners;
    uint256 private _nextAgentId = 1;

    function setOwner(uint256 agentId, address owner) external {
        _owners[agentId] = owner;
    }

    function ownerOf(uint256 agentId) external view override returns (address) {
        return _owners[agentId];
    }

    function mint(address to) external override returns (uint256 agentId) {
        agentId = _nextAgentId++;
        _owners[agentId] = to;
    }
}

contract ChitinSoulRegistryTest is Test {
    ChitinSoulRegistry public registry;
    ChitinSoulRegistry public implementation;
    MockOwnerVerifier public mockVerifier;
    MockERC8004Registry public mockErc8004Registry;

    address public contractOwner = address(0x1);
    address public holder = address(0x2); // Agent's Smart Account
    address public recordOwner = address(0x3); // SBT owner (human/multisig)
    address public operator = address(0x4);
    address public randomUser = address(0x5);
    address public liabilityAddress = address(0x6);

    bytes32 public soulHash = keccak256("soul content");
    bytes32 public soulMerkleRoot = keccak256("merkle root");
    bytes32 public soulSalt = keccak256("random salt");
    bytes32 public arweaveTxId = keccak256("ar://abc123");

    event ProvisionalMinted(
        uint256 indexed tokenId,
        address indexed holder,
        address indexed owner,
        string agentName,
        bytes32 soulHash,
        uint256 erc8004AgentId
    );

    event GenesisSealed(uint256 indexed tokenId, address indexed sealedBy, uint64 sealTimestamp);
    event Locked(uint256 tokenId);
    event EvolutionAppended(
        uint256 indexed tokenId,
        uint256 indexed evolutionId,
        ChitinSoulRegistry.ChangeType changeType,
        bytes32 newSoulHash
    );
    event SoulResealed(
        uint256 indexed tokenId,
        uint256 indexed erc8004AgentId,
        address indexed newSealedBy,
        bytes32 newSoulHash
    );

    event AgentBurned(uint256 indexed tokenId, address indexed owner, string reason);

    event AgentReincarnated(
        uint256 indexed parentTokenId,
        uint256 indexed newTokenId,
        uint256 indexed erc8004AgentId,
        string agentName
    );

    event PassportAndSoulMinted(
        uint256 indexed tokenId,
        uint256 indexed erc8004AgentId,
        address indexed owner,
        string agentName
    );

    event OwnerAttested(
        uint256 indexed tokenId,
        address indexed provider,
        uint8 trustTier,
        bytes32 attestationId
    );

    function setUp() public {
        // Deploy implementation
        implementation = new ChitinSoulRegistry();

        // Deploy mock ERC-8004 registry
        mockErc8004Registry = new MockERC8004Registry();

        // Deploy proxy with ERC-8004 registry
        bytes memory initData = abi.encodeWithSelector(
            ChitinSoulRegistry.initialize.selector,
            contractOwner,
            address(mockErc8004Registry)
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);

        registry = ChitinSoulRegistry(address(proxy));

        // Deploy mock verifier
        mockVerifier = new MockOwnerVerifier();
    }

    // Helper function to mint a token with default values (no ERC-8004 binding)
    function _mintDefault(string memory agentName) internal returns (uint256) {
        vm.prank(contractOwner);
        return registry.mint(
            holder,
            agentName,
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50, // autonomyLevel
            operator,
            liabilityAddress,
            0, // parentTokenId (human-created)
            0, // fleetId (independent)
            arweaveTxId,
            0,  // erc8004AgentId (no binding)
            address(0), // verifier (no attestation)
            ""  // proof
        );
    }

    // Helper function to mint a token with ERC-8004 binding
    function _mintWithErc8004(string memory agentName, uint256 erc8004AgentId) internal returns (uint256) {
        vm.prank(contractOwner);
        return registry.mint(
            holder,
            agentName,
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            erc8004AgentId,
            address(0), // verifier (no attestation)
            ""  // proof
        );
    }

    // Helper function to mint a token with attestation
    function _mintWithAttestation(string memory agentName, address verifier, bytes memory proof) internal returns (uint256) {
        vm.prank(contractOwner);
        return registry.mint(
            holder,
            agentName,
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            0, // parentTokenId (human-created)
            0,
            arweaveTxId,
            0,  // erc8004AgentId (no binding)
            verifier,
            proof
        );
    }

    // ═══════════════════════════════════════════════════
    // Mint Tests
    // ═══════════════════════════════════════════════════

    function test_Mint() public {
        vm.expectEmit(true, true, true, true);
        emit Locked(1);

        vm.expectEmit(true, true, true, true);
        emit ProvisionalMinted(1, holder, contractOwner, "test-agent", soulHash, 0);

        vm.prank(contractOwner);
        uint256 tokenId = registry.mint(
            holder,
            "test-agent",
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0), // verifier
            ""  // proof
        );

        assertEq(tokenId, 1);
        assertEq(registry.ownerOf(tokenId), holder);

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.soulHash, soulHash);
        assertEq(record.soulMerkleRoot, soulMerkleRoot);
        assertEq(record.soulSalt, soulSalt);
        assertEq(record.owner, contractOwner);
        assertEq(record.operator, operator);
        assertEq(record.liabilityAddress, liabilityAddress);
        assertEq(uint8(record.genesisStatus), uint8(ChitinSoulRegistry.GenesisStatus.Provisional));
        assertEq(uint8(record.agentType), uint8(ChitinSoulRegistry.AgentType.Assistant));
        assertEq(record.autonomyLevel, 50);
        assertEq(record.parentTokenId, 0);
        assertEq(record.fleetId, 0);
        assertEq(record.erc8004AgentId, 0);
        assertEq(record.sealedBy, address(0));
    }

    function test_Mint_WithErc8004AgentId() public {
        uint256 agentId = 12345;

        // Set up mock ERC-8004 ownership (contractOwner is now the minter/record owner)
        mockErc8004Registry.setOwner(agentId, contractOwner);

        vm.expectEmit(true, true, true, true);
        emit ProvisionalMinted(1, holder, contractOwner, "test-agent", soulHash, agentId);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        assertEq(tokenId, 1);

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.erc8004AgentId, agentId);

        // Check reverse mapping
        assertEq(registry.getTokenIdByAgentId(agentId), tokenId);
        assertEq(registry.getErc8004AgentId(tokenId), agentId);
    }

    function test_Mint_RevertIfErc8004AgentIdAlreadyBound() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        // First mint succeeds (helper does vm.prank(contractOwner))
        _mintWithErc8004("first-agent", agentId);

        // Second mint with same agent ID fails
        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.Erc8004AgentIdAlreadyBound.selector, agentId));
        registry.mint(
            holder, "second-agent", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId,
            agentId, address(0), ""
        );
    }

    function test_Mint_RevertIfErc8004AgentIdNotOwned() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, randomUser); // Not contractOwner

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.Erc8004AgentIdNotOwned.selector, agentId, contractOwner));
        registry.mint(
            holder, "test-agent", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId,
            agentId, address(0), ""
        );
    }

    function test_Mint_IncrementTokenId() public {
        uint256 tokenId1 = _mintDefault("agent-one");

        vm.prank(contractOwner);
        uint256 tokenId2 = registry.mint(
            holder,
            "agent-two",
            keccak256("soul2"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Specialist,
            80,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );

        assertEq(tokenId1, 1);
        assertEq(tokenId2, 2);
        assertEq(registry.getTokenCounter(), 3);
    }

    function test_Mint_RevertIfNameTaken() public {
        _mintDefault("taken-name");

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.NameAlreadyTaken.selector, "taken-name"));
        registry.mint(
            holder, "taken-name", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );
    }

    function test_Mint_RevertIfInvalidName() public {
        vm.startPrank(contractOwner);

        // Empty name
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.InvalidName.selector, ""));
        registry.mint(
            holder, "", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );

        // Uppercase
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.InvalidName.selector, "UpperCase"));
        registry.mint(
            holder, "UpperCase", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );

        // Starts with hyphen
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.InvalidName.selector, "-invalid"));
        registry.mint(
            holder, "-invalid", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );

        // Ends with hyphen
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.InvalidName.selector, "invalid-"));
        registry.mint(
            holder, "invalid-", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );

        // Too short (less than 3 chars)
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.InvalidName.selector, "ab"));
        registry.mint(
            holder, "ab", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );

        vm.stopPrank();
    }

    function test_Mint_RevertIfZeroHolder() public {
        vm.prank(contractOwner);
        vm.expectRevert(ChitinSoulRegistry.InvalidHolder.selector);
        registry.mint(
            address(0), "test-agent", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );
    }

    function test_Mint_RevertIfZeroSoulHash() public {
        vm.prank(contractOwner);
        vm.expectRevert(ChitinSoulRegistry.InvalidSoulHash.selector);
        registry.mint(
            holder, "test-agent", bytes32(0), soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );
    }

    function test_Mint_RevertNonOwner() public {
        vm.prank(recordOwner);
        vm.expectRevert();
        registry.mint(
            holder, "test-agent", soulHash, soulMerkleRoot, soulSalt,
            ChitinSoulRegistry.AgentType.Assistant, 50, operator, liabilityAddress, 0, 0, arweaveTxId, 0, address(0), ""
        );
    }

    // ═══════════════════════════════════════════════════
    // Seal Tests
    // ═══════════════════════════════════════════════════

    function test_Seal() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner); // record owner can seal
        vm.expectEmit(true, true, true, true);
        emit GenesisSealed(tokenId, contractOwner, uint64(block.timestamp));
        registry.seal(tokenId);

        assertTrue(registry.isSealed(tokenId));

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(uint8(record.genesisStatus), uint8(ChitinSoulRegistry.GenesisStatus.Sealed));
        assertEq(record.sealTimestamp, uint64(block.timestamp));
        assertEq(record.sealedBy, contractOwner);
    }

    function test_Seal_RecordsSealedBy() public {
        uint256 tokenId = _mintDefault("test-agent");

        // Operator seals
        vm.prank(operator);
        registry.seal(tokenId);

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.sealedBy, operator);
    }

    function test_Seal_ByOperator() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(operator); // operator can also seal
        registry.seal(tokenId);

        assertTrue(registry.isSealed(tokenId));
    }

    function test_Seal_RevertIfAlreadySealed() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.AlreadySealed.selector, tokenId));
        registry.seal(tokenId);
    }

    function test_Seal_RevertIfDeadlinePassed() public {
        uint256 tokenId = _mintDefault("test-agent");

        // Fast forward past deadline
        vm.warp(block.timestamp + 31 days);

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.SealDeadlinePassed.selector, tokenId));
        registry.seal(tokenId);
    }

    function test_Seal_RevertIfNotOwnerOrOperator() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.NotOwnerOrOperator.selector, tokenId));
        registry.seal(tokenId);
    }

    // ═══════════════════════════════════════════════════
    // CheckSoulValidity Tests
    // ═══════════════════════════════════════════════════

    function test_CheckSoulValidity_NotSealed() public {
        uint256 tokenId = _mintDefault("test-agent");

        (bool valid, address sealedBy, address currentOwner) = registry.checkSoulValidity(tokenId);

        assertFalse(valid);
        assertEq(sealedBy, address(0));
        assertEq(currentOwner, address(0));
    }

    function test_CheckSoulValidity_NoErc8004Binding() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        (bool valid, address sealedBy, address currentOwner) = registry.checkSoulValidity(tokenId);

        assertTrue(valid);
        assertEq(sealedBy, contractOwner);
        assertEq(currentOwner, address(0));
    }

    function test_CheckSoulValidity_ValidBinding() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        // Transfer passport to SBT holder (simulates MINTER -> user transfer)
        mockErc8004Registry.setOwner(agentId, holder);

        vm.prank(contractOwner);
        registry.seal(tokenId);

        (bool valid, address sealedBy, address currentOwner) = registry.checkSoulValidity(tokenId);

        // Valid because passport owner (holder) == SBT ownerOf (holder)
        assertTrue(valid);
        assertEq(sealedBy, contractOwner);
        assertEq(currentOwner, holder);
    }

    function test_CheckSoulValidity_InvalidBinding() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        // Transfer passport to SBT holder first
        mockErc8004Registry.setOwner(agentId, holder);

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // Passport ownership changes to someone else (not the SBT holder)
        mockErc8004Registry.setOwner(agentId, randomUser);

        (bool valid, address sealedBy, address currentOwner) = registry.checkSoulValidity(tokenId);

        // Invalid because passport owner (randomUser) != SBT ownerOf (holder)
        assertFalse(valid);
        assertEq(sealedBy, contractOwner);
        assertEq(currentOwner, randomUser);
    }

    // ═══════════════════════════════════════════════════
    // Reseal Tests
    // ═══════════════════════════════════════════════════

    function test_Reseal() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // Passport ownership changes
        mockErc8004Registry.setOwner(agentId, randomUser);

        // Record owner transfers ownership of the record
        // For this test, we'll use the same record owner but pretend they're the new passport owner
        mockErc8004Registry.setOwner(agentId, contractOwner);

        bytes32 newSoulHash = keccak256("new soul");
        bytes32 newArweaveTxId = keccak256("ar://newtx");

        vm.prank(contractOwner);
        vm.expectEmit(true, true, true, true);
        emit SoulResealed(tokenId, agentId, contractOwner, newSoulHash);
        registry.reseal(tokenId, newSoulHash, bytes32(0), bytes32(0), newArweaveTxId);

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.soulHash, newSoulHash);
        assertEq(record.arweaveTxId, newArweaveTxId);
        assertEq(record.sealedBy, contractOwner);
    }

    function test_Reseal_KeepExistingValues() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // Reseal with zeros to keep existing values
        vm.prank(contractOwner);
        registry.reseal(tokenId, bytes32(0), bytes32(0), bytes32(0), bytes32(0));

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.soulHash, soulHash); // Unchanged
        assertEq(record.soulMerkleRoot, soulMerkleRoot); // Unchanged
        assertEq(record.soulSalt, soulSalt); // Unchanged
        assertEq(record.arweaveTxId, arweaveTxId); // Unchanged
    }

    function test_Reseal_RevertIfNotRecordOwner() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        vm.prank(contractOwner);
        registry.seal(tokenId);

        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.OnlyRecordOwnerCanReseal.selector, tokenId));
        registry.reseal(tokenId, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_Reseal_RevertIfNotSealed() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        // Not sealed

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.SoulNotSealed.selector, tokenId));
        registry.reseal(tokenId, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_Reseal_RevertIfNoErc8004Binding() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        vm.prank(contractOwner);
        vm.expectRevert(ChitinSoulRegistry.Erc8004RegistryNotSet.selector);
        registry.reseal(tokenId, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_Reseal_RevertIfNotPassportOwner() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // Change passport ownership
        mockErc8004Registry.setOwner(agentId, randomUser);

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.Erc8004AgentIdNotOwned.selector, agentId, contractOwner));
        registry.reseal(tokenId, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    // ═══════════════════════════════════════════════════
    // ERC-8004 Uniqueness Tests
    // ═══════════════════════════════════════════════════

    function test_Erc8004AgentIdUniqueness() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("first-agent", agentId);

        // Verify mapping
        assertEq(registry.getTokenIdByAgentId(agentId), tokenId);

        // Burn the token (record owner is contractOwner)
        vm.prank(contractOwner);
        registry.burn(tokenId, "deprecated");

        // Agent ID should be released
        assertEq(registry.getTokenIdByAgentId(agentId), 0);

        // Should be able to mint with same agent ID again
        uint256 newTokenId = _mintWithErc8004("second-agent", agentId);

        assertEq(registry.getTokenIdByAgentId(agentId), newTokenId);
    }

    // ═══════════════════════════════════════════════════
    // Evolution Tests
    // ═══════════════════════════════════════════════════

    function test_AppendEvolution() public {
        // Mint and seal
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // Append evolution (Technical category - e.g., model upgrade)
        bytes32 newSoulHash = keccak256("new soul");
        bytes32 newArweaveTxId = keccak256("ar://newext123");

        vm.prank(contractOwner);
        vm.expectEmit(true, true, true, true);
        emit EvolutionAppended(tokenId, 0, ChitinSoulRegistry.ChangeType.Technical, newSoulHash);
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Technical, newSoulHash, newArweaveTxId);

        ChitinSoulRegistry.EvolutionRecord[] memory history = registry.getEvolutionHistory(tokenId);
        assertEq(history.length, 1);
        assertEq(uint8(history[0].changeType), uint8(ChitinSoulRegistry.ChangeType.Technical));
        assertEq(history[0].newSoulHash, newSoulHash);
        assertEq(history[0].arweaveTxId, newArweaveTxId);
        assertEq(history[0].tokenId, tokenId);
        assertEq(history[0].evolutionId, 0);
    }

    function test_AppendEvolution_ByOperator() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // Operator can also append evolution (Certification category)
        vm.prank(operator);
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Certification, bytes32(0), arweaveTxId);

        assertEq(registry.getEvolutionCount(tokenId), 1);
    }

    function test_AppendEvolution_RevertIfNotSealed() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.NotSealed.selector, tokenId));
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Technical, bytes32(0), arweaveTxId);
    }

    function test_GetEvolutionCount() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        assertEq(registry.getEvolutionCount(tokenId), 0);

        vm.prank(contractOwner);
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Technical, bytes32(0), arweaveTxId);

        vm.prank(contractOwner);
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Achievement, bytes32(0), arweaveTxId);

        assertEq(registry.getEvolutionCount(tokenId), 2);
    }

    function test_AppendEvolution_AllCategories() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // Test all evolution categories
        vm.startPrank(contractOwner);

        // Technical (0)
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Technical, bytes32(0), arweaveTxId);
        // Certification (1)
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Certification, bytes32(0), arweaveTxId);
        // Achievement (2)
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Achievement, bytes32(0), arweaveTxId);
        // Experience (3)
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Experience, bytes32(0), arweaveTxId);
        // Endorsement (4)
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Endorsement, bytes32(0), arweaveTxId);
        // Other (5)
        registry.appendEvolution(tokenId, ChitinSoulRegistry.ChangeType.Other, bytes32(0), arweaveTxId);

        vm.stopPrank();

        ChitinSoulRegistry.EvolutionRecord[] memory history = registry.getEvolutionHistory(tokenId);
        assertEq(history.length, 6);
        assertEq(uint8(history[0].changeType), uint8(ChitinSoulRegistry.ChangeType.Technical));
        assertEq(uint8(history[1].changeType), uint8(ChitinSoulRegistry.ChangeType.Certification));
        assertEq(uint8(history[2].changeType), uint8(ChitinSoulRegistry.ChangeType.Achievement));
        assertEq(uint8(history[3].changeType), uint8(ChitinSoulRegistry.ChangeType.Experience));
        assertEq(uint8(history[4].changeType), uint8(ChitinSoulRegistry.ChangeType.Endorsement));
        assertEq(uint8(history[5].changeType), uint8(ChitinSoulRegistry.ChangeType.Other));
    }

    // ═══════════════════════════════════════════════════
    // Soulbound Tests
    // ═══════════════════════════════════════════════════

    function test_Soulbound_TransferReverts() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(holder);
        vm.expectRevert(ChitinSoulRegistry.SoulboundTransferNotAllowed.selector);
        registry.transferFrom(holder, randomUser, tokenId);
    }

    function test_Soulbound_SafeTransferReverts() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(holder);
        vm.expectRevert(ChitinSoulRegistry.SoulboundTransferNotAllowed.selector);
        registry.safeTransferFrom(holder, randomUser, tokenId);
    }

    function test_Locked_AlwaysTrue() public {
        uint256 tokenId = _mintDefault("test-agent");

        assertTrue(registry.locked(tokenId));
    }

    function test_Approve_Reverts() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(holder);
        vm.expectRevert(ChitinSoulRegistry.SoulboundTransferNotAllowed.selector);
        registry.approve(randomUser, tokenId);
    }

    function test_SetApprovalForAll_Reverts() public {
        vm.prank(holder);
        vm.expectRevert(ChitinSoulRegistry.SoulboundTransferNotAllowed.selector);
        registry.setApprovalForAll(randomUser, true);
    }

    function test_SupportsInterface_EIP5192() public view {
        bytes4 EIP5192_INTERFACE_ID = 0xb45a3c0e;
        assertTrue(registry.supportsInterface(EIP5192_INTERFACE_ID));
    }

    // ═══════════════════════════════════════════════════
    // Burn Tests
    // ═══════════════════════════════════════════════════

    function test_Burn() public {
        uint256 tokenId = _mintDefault("test-agent");

        // Only record owner can burn (record owner is now contractOwner)
        vm.prank(contractOwner);
        vm.expectEmit(true, true, true, true);
        emit AgentBurned(tokenId, contractOwner, "server_death");
        registry.burn(tokenId, "server_death");

        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.TokenDoesNotExist.selector, tokenId));
        registry.getGenesisRecord(tokenId);

        // Name should be available again
        assertEq(registry.getTokenIdByName("test-agent"), 0);
    }

    function test_Burn_WithReason() public {
        uint256 tokenId = _mintDefault("test-agent");

        uint256 burnTimestamp = block.timestamp;

        vm.prank(contractOwner);
        vm.expectEmit(true, true, true, true);
        emit AgentBurned(tokenId, contractOwner, "compromised");
        registry.burn(tokenId, "compromised");

        // Check burned token info is recorded with full BurnInfo
        (bool burned, address originalOwner, string memory reason, uint64 timestamp) = registry.getBurnedTokenInfo(tokenId);
        assertTrue(burned);
        assertEq(originalOwner, contractOwner);
        assertEq(reason, "compromised");
        assertEq(timestamp, uint64(burnTimestamp));
    }

    function test_Burn_ReleasesErc8004AgentId() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        assertEq(registry.getTokenIdByAgentId(agentId), tokenId);

        vm.prank(contractOwner);
        registry.burn(tokenId, "deprecated");

        // Agent ID should be released
        assertEq(registry.getTokenIdByAgentId(agentId), 0);
    }

    function test_Burn_RevertIfNotOwner() public {
        uint256 tokenId = _mintDefault("test-agent");

        // Holder cannot burn
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.OnlyOwnerCanBurn.selector, tokenId));
        registry.burn(tokenId, "test");

        // Operator cannot burn
        vm.prank(operator);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.OnlyOwnerCanBurn.selector, tokenId));
        registry.burn(tokenId, "test");

        // Random user cannot burn
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.OnlyOwnerCanBurn.selector, tokenId));
        registry.burn(tokenId, "test");
    }

    // ═══════════════════════════════════════════════════
    // Verification Tests
    // ═══════════════════════════════════════════════════

    function test_VerifyIntegrity() public {
        uint256 tokenId = _mintDefault("test-agent");

        assertTrue(registry.verifyIntegrity(tokenId, soulHash));
        assertFalse(registry.verifyIntegrity(tokenId, keccak256("wrong")));
    }

    function test_GetTokenIdByName() public {
        uint256 tokenId = _mintDefault("test-agent");

        assertEq(registry.getTokenIdByName("test-agent"), tokenId);
        assertEq(registry.getTokenIdByName("nonexistent"), 0);
    }

    // ═══════════════════════════════════════════════════
    // Alignment Score Tests
    // ═══════════════════════════════════════════════════

    function test_UpdateAlignment() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.updateAlignment(tokenId, 85);

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.lastAlignmentScore, 85);
        assertEq(record.lastSnapshotTimestamp, uint64(block.timestamp));
    }

    function test_UpdateAlignment_RevertIfInvalidScore() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        vm.expectRevert(ChitinSoulRegistry.InvalidAlignmentScore.selector);
        registry.updateAlignment(tokenId, 101); // Max is 100
    }

    function test_CheckFreshness() public {
        uint256 tokenId = _mintDefault("test-agent");

        // No snapshot yet
        assertFalse(registry.checkFreshness(tokenId, 1 days));

        // Update alignment
        vm.prank(contractOwner);
        registry.updateAlignment(tokenId, 90);

        // Fresh enough
        assertTrue(registry.checkFreshness(tokenId, 1 days));

        // Warp time
        vm.warp(block.timestamp + 2 days);

        // Not fresh anymore
        assertFalse(registry.checkFreshness(tokenId, 1 days));
    }

    // ═══════════════════════════════════════════════════
    // Binding Tests
    // ═══════════════════════════════════════════════════

    function test_SetBinding() public {
        uint256 tokenId1 = _mintDefault("agent-one");
        uint256 tokenId2 = _mintDefault("agent-two");

        bytes32 contextHash = keccak256("collaboration context");

        vm.prank(contractOwner);
        registry.setBinding(tokenId1, tokenId2, ChitinSoulRegistry.TrustLevel.Verified, contextHash);

        ChitinSoulRegistry.AgentBinding[] memory bindings = registry.getBindings(tokenId1);
        assertEq(bindings.length, 1);
        assertEq(bindings[0].fromTokenId, tokenId1);
        assertEq(bindings[0].toTokenId, tokenId2);
        assertEq(uint8(bindings[0].trustLevel), uint8(ChitinSoulRegistry.TrustLevel.Verified));
        assertEq(bindings[0].contextHash, contextHash);
    }

    // ═══════════════════════════════════════════════════
    // Owner Verifier Tests
    // ═══════════════════════════════════════════════════

    function test_AddVerifier() public {
        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        assertTrue(registry.isApprovedVerifier(address(mockVerifier)));

        address[] memory verifiers = registry.getApprovedVerifiers();
        assertEq(verifiers.length, 1);
        assertEq(verifiers[0], address(mockVerifier));
    }

    function test_AddVerifier_RevertIfNotContractOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        registry.addVerifier(address(mockVerifier));
    }

    function test_AddVerifier_RevertIfAlreadyApproved() public {
        vm.startPrank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.VerifierAlreadyApproved.selector, address(mockVerifier)));
        registry.addVerifier(address(mockVerifier));
        vm.stopPrank();
    }

    function test_RemoveVerifier() public {
        vm.startPrank(contractOwner);
        registry.addVerifier(address(mockVerifier));
        registry.removeVerifier(address(mockVerifier));
        vm.stopPrank();

        assertFalse(registry.isApprovedVerifier(address(mockVerifier)));
        assertEq(registry.getApprovedVerifiers().length, 0);
    }

    function test_VerifyOwner() public {
        // Add verifier
        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        // Mint token
        uint256 tokenId = _mintDefault("test-agent");

        // Verify owner (record owner is contractOwner)
        vm.prank(contractOwner);
        registry.verifyOwner(tokenId, address(mockVerifier), contractOwner, "");

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.ownerAttestation.provider, address(mockVerifier));
        assertEq(record.ownerAttestation.trustTier, 2);
        assertEq(record.ownerAttestation.attestationId, keccak256("mock-attestation"));
    }

    function test_VerifyOwner_RevertIfVerifierNotApproved() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.VerifierNotApproved.selector, address(mockVerifier)));
        registry.verifyOwner(tokenId, address(mockVerifier), contractOwner, "");
    }

    function test_VerifyOwner_RevertIfAlreadyAttested() public {
        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.verifyOwner(tokenId, address(mockVerifier), contractOwner, "");

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.AlreadyAttested.selector, tokenId));
        registry.verifyOwner(tokenId, address(mockVerifier), contractOwner, "");
    }

    function test_VerifyOwner_RevertIfAgentSpawned() public {
        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        // Mint parent agent
        uint256 parentId = _mintDefault("parent-agent");

        // Mint child agent (agent-spawned)
        vm.prank(contractOwner);
        uint256 childId = registry.mint(
            holder,
            "child-agent",
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            parentId, // Has parent - agent-spawned
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );

        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.AgentSpawnedCannotAttest.selector, childId));
        registry.verifyOwner(childId, address(mockVerifier), contractOwner, "");
    }

    // ═══════════════════════════════════════════════════
    // ERC-8004 Registry Management Tests
    // ═══════════════════════════════════════════════════

    function test_SetErc8004Registry() public {
        address newRegistry = address(0x999);

        vm.prank(contractOwner);
        registry.setErc8004Registry(newRegistry);

        assertEq(registry.erc8004Registry(), newRegistry);
    }

    function test_SetErc8004Registry_RevertIfNotOwner() public {
        vm.prank(randomUser);
        vm.expectRevert();
        registry.setErc8004Registry(address(0x999));
    }

    // ═══════════════════════════════════════════════════
    // Fuzz Tests
    // ═══════════════════════════════════════════════════

    function testFuzz_MintWithDifferentHashes(bytes32 soul, bytes32 merkle, bytes32 salt) public {
        vm.assume(soul != bytes32(0));

        vm.prank(contractOwner);
        uint256 tokenId = registry.mint(
            holder,
            "fuzz-agent",
            soul,
            merkle,
            salt,
            ChitinSoulRegistry.AgentType.Other,
            100,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.soulHash, soul);
        assertEq(record.soulMerkleRoot, merkle);
        assertEq(record.soulSalt, salt);
    }

    function testFuzz_AutonomyLevel(uint8 level) public {
        vm.prank(contractOwner);
        uint256 tokenId = registry.mint(
            holder,
            "autonomy-agent",
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            level,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.autonomyLevel, level);
    }

    // ═══════════════════════════════════════════════════
    // TokenURI Tests (Text-only On-chain SVG)
    // ═══════════════════════════════════════════════════

    function test_TokenURI_ReturnsValidDataURI() public {
        uint256 tokenId = _mintDefault("test-agent");

        string memory uri = registry.tokenURI(tokenId);

        // Should start with data:application/json;base64,
        assertTrue(bytes(uri).length > 0);
        assertTrue(_startsWith(uri, "data:application/json;base64,"));
    }

    function test_TokenURI_RevertIfTokenDoesNotExist() public {
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.TokenDoesNotExist.selector, 999));
        registry.tokenURI(999);
    }

    function _startsWith(string memory str, string memory prefix) internal pure returns (bool) {
        bytes memory strBytes = bytes(str);
        bytes memory prefixBytes = bytes(prefix);

        if (strBytes.length < prefixBytes.length) {
            return false;
        }

        for (uint i = 0; i < prefixBytes.length; i++) {
            if (strBytes[i] != prefixBytes[i]) {
                return false;
            }
        }

        return true;
    }

    // ═══════════════════════════════════════════════════
    // Reincarnation Tests
    // ═══════════════════════════════════════════════════

    function test_Reincarnate() public {
        // Mint and burn original agent
        uint256 originalTokenId = _mintDefault("original-agent");

        vm.prank(contractOwner);
        registry.burn(originalTokenId, "server_death");

        // Reincarnate with new soul (record owner is contractOwner)
        bytes32 newSoulHash = keccak256("new soul content");
        bytes32 newMerkleRoot = keccak256("new merkle root");
        bytes32 newSalt = keccak256("new salt");
        bytes32 newArweaveTxId = keccak256("ar://newtx123");

        vm.prank(contractOwner);
        vm.expectEmit(true, true, true, true);
        emit AgentReincarnated(originalTokenId, 2, 0, "reborn-agent");
        uint256 newTokenId = registry.reincarnate(
            originalTokenId,
            0, // No ERC-8004 binding
            "reborn-agent",
            newSoulHash,
            newMerkleRoot,
            newSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            newArweaveTxId
        );

        assertEq(newTokenId, 2);

        // Verify new record
        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(newTokenId);
        assertEq(record.soulHash, newSoulHash);
        assertEq(record.soulMerkleRoot, newMerkleRoot);
        assertEq(record.soulSalt, newSalt);
        assertEq(record.owner, contractOwner);
        assertEq(record.operator, operator);
        assertEq(record.parentTokenId, originalTokenId); // Links to burned token
        assertEq(uint8(record.genesisStatus), uint8(ChitinSoulRegistry.GenesisStatus.Provisional));

        // New token is owned by the record owner (contractOwner)
        assertEq(registry.ownerOf(newTokenId), contractOwner);
    }

    function test_Reincarnate_WithSameName() public {
        // Mint and burn original agent
        uint256 originalTokenId = _mintDefault("phoenix-agent");

        vm.prank(contractOwner);
        registry.burn(originalTokenId, "server_death");

        // Reincarnate with same name (should be available after burn)
        vm.prank(contractOwner);
        uint256 newTokenId = registry.reincarnate(
            originalTokenId,
            0,
            "phoenix-agent", // Same name
            keccak256("new soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );

        assertEq(registry.getTokenIdByName("phoenix-agent"), newTokenId);
    }

    function test_Reincarnate_WithErc8004() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        // Mint and burn original agent
        uint256 originalTokenId = _mintDefault("original-agent");

        vm.prank(contractOwner);
        registry.burn(originalTokenId, "server_death");

        // Reincarnate with ERC-8004 binding
        vm.prank(contractOwner);
        vm.expectEmit(true, true, true, true);
        emit AgentReincarnated(originalTokenId, 2, agentId, "reborn-agent");
        uint256 newTokenId = registry.reincarnate(
            originalTokenId,
            agentId,
            "reborn-agent",
            keccak256("new soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(newTokenId);
        assertEq(record.erc8004AgentId, agentId);
        assertEq(registry.getTokenIdByAgentId(agentId), newTokenId);
    }

    function test_Reincarnate_RevertIfParentNotBurned() public {
        // Mint but don't burn
        uint256 tokenId = _mintDefault("test-agent");

        // Try to reincarnate from non-burned token
        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.ParentTokenNotBurned.selector, tokenId));
        registry.reincarnate(
            tokenId,
            0,
            "new-agent",
            keccak256("soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );
    }

    function test_Reincarnate_RevertIfParentNeverExisted() public {
        // Try to reincarnate from non-existent token
        vm.prank(recordOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.ParentTokenNeverExisted.selector, 9999));
        registry.reincarnate(
            9999,
            0,
            "new-agent",
            keccak256("soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );
    }

    function test_Reincarnate_RevertIfNotOriginalOwner() public {
        // Mint and burn
        uint256 originalTokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.burn(originalTokenId, "server_death");

        // Try to reincarnate as different user
        vm.prank(randomUser);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.OnlyParentOwnerCanReincarnate.selector, originalTokenId));
        registry.reincarnate(
            originalTokenId,
            0,
            "new-agent",
            keccak256("soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );
    }

    function test_Reincarnate_RevertIfNameTaken() public {
        // Mint first agent
        _mintDefault("taken-name");

        // Mint and burn second agent
        vm.prank(contractOwner);
        uint256 tokenId = registry.mint(
            holder,
            "to-burn",
            keccak256("soul2"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );

        vm.prank(contractOwner);
        registry.burn(tokenId, "test");

        // Try to reincarnate with taken name
        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.NameAlreadyTaken.selector, "taken-name"));
        registry.reincarnate(
            tokenId,
            0,
            "taken-name",
            keccak256("soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );
    }

    function test_Reincarnate_RevertIfErc8004NotOwned() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, randomUser); // Not contractOwner

        // Mint and burn
        uint256 originalTokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.burn(originalTokenId, "server_death");

        // Try to reincarnate with unowned ERC-8004
        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.Erc8004AgentIdNotOwned.selector, agentId, contractOwner));
        registry.reincarnate(
            originalTokenId,
            agentId,
            "new-agent",
            keccak256("soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );
    }

    function test_Reincarnate_RevertIfErc8004AlreadyBound() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        // Mint with ERC-8004 binding (this uses the agentId)
        _mintWithErc8004("first-agent", agentId);

        // Mint and burn another agent
        vm.prank(contractOwner);
        uint256 tokenId = registry.mint(
            holder,
            "to-burn",
            keccak256("soul2"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );

        vm.prank(contractOwner);
        registry.burn(tokenId, "test");

        // Try to reincarnate with already-bound ERC-8004
        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.Erc8004AgentIdAlreadyBound.selector, agentId));
        registry.reincarnate(
            tokenId,
            agentId,
            "new-agent",
            keccak256("soul"),
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );
    }

    function test_GetBurnedTokenInfo() public {
        // Mint and burn
        uint256 tokenId = _mintDefault("test-agent");

        // Before burn
        (bool burned, address originalOwner, string memory reason, uint64 timestamp) = registry.getBurnedTokenInfo(tokenId);
        assertFalse(burned);
        assertEq(originalOwner, address(0));
        assertEq(bytes(reason).length, 0);
        assertEq(timestamp, 0);

        uint256 burnTime = block.timestamp;
        vm.prank(contractOwner);
        registry.burn(tokenId, "server_death");

        // After burn
        (burned, originalOwner, reason, timestamp) = registry.getBurnedTokenInfo(tokenId);
        assertTrue(burned);
        assertEq(originalOwner, contractOwner);
        assertEq(reason, "server_death");
        assertEq(timestamp, uint64(burnTime));
    }

    // ═══════════════════════════════════════════════════
    // Burn & Reincarnation Soul Continuity Tests
    // ═══════════════════════════════════════════════════

    function test_Reincarnate_SoulContinuity() public {
        // Test "soul continuity" - same soulHash means same soul
        uint256 originalTokenId = _mintDefault("original-soul");

        // Seal the original
        vm.prank(contractOwner);
        registry.seal(originalTokenId);

        ChitinSoulRegistry.GenesisRecord memory originalRecord = registry.getGenesisRecord(originalTokenId);
        bytes32 originalSoulHash = originalRecord.soulHash;

        // Burn the original
        vm.prank(contractOwner);
        registry.burn(originalTokenId, "server_death");

        // Reincarnate with SAME soulHash (soul continuity)
        vm.prank(contractOwner);
        uint256 newTokenId = registry.reincarnate(
            originalTokenId,
            0,
            "reborn-soul",
            originalSoulHash, // Same soul hash = soul continuity
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );

        ChitinSoulRegistry.GenesisRecord memory newRecord = registry.getGenesisRecord(newTokenId);

        // Verify soul continuity
        assertEq(newRecord.soulHash, originalSoulHash, "Soul hash should be the same (soul continuity)");
        assertEq(newRecord.parentTokenId, originalTokenId, "Should reference burned token as parent");

        // Verify burn info is still accessible
        (bool burned, address owner, string memory reason, uint64 timestamp) = registry.getBurnedTokenInfo(originalTokenId);
        assertTrue(burned);
        assertEq(owner, contractOwner);
        assertEq(reason, "server_death");
        assertTrue(timestamp > 0);
    }

    function test_Burn_MultipleReasons() public {
        // Test different burn reasons
        string[4] memory reasons = ["server_death", "compromised", "deprecated", "migration"];

        for (uint256 i = 0; i < reasons.length; i++) {
            string memory agentName = string(abi.encodePacked("agent-", vm.toString(i)));

            vm.prank(contractOwner);
            uint256 tokenId = registry.mint(
                holder,
                agentName,
                keccak256(abi.encodePacked("soul", i)),
                soulMerkleRoot,
                soulSalt,
                ChitinSoulRegistry.AgentType.Assistant,
                50,
                operator,
                liabilityAddress,
                0,
                0,
                arweaveTxId,
                0,
                address(0),
                ""
            );

            vm.prank(contractOwner);
            registry.burn(tokenId, reasons[i]);

            (, , string memory recordedReason, ) = registry.getBurnedTokenInfo(tokenId);
            assertEq(recordedReason, reasons[i], "Burn reason should be recorded correctly");
        }
    }

    // ═══════════════════════════════════════════════════
    // Pause/Unpause Emergency Functions Tests
    // ═══════════════════════════════════════════════════

    function test_Pause() public {
        // Only contract owner can pause
        vm.prank(contractOwner);
        registry.pause();
        assertTrue(registry.paused());
    }

    function test_Pause_RevertIfNotOwner() public {
        vm.prank(recordOwner);
        vm.expectRevert();
        registry.pause();
    }

    function test_Unpause() public {
        vm.prank(contractOwner);
        registry.pause();
        assertTrue(registry.paused());

        vm.prank(contractOwner);
        registry.unpause();
        assertFalse(registry.paused());
    }

    function test_Unpause_RevertIfNotOwner() public {
        vm.prank(contractOwner);
        registry.pause();

        vm.prank(recordOwner);
        vm.expectRevert();
        registry.unpause();
    }

    function test_Mint_RevertWhenPaused() public {
        vm.prank(contractOwner);
        registry.pause();

        vm.prank(contractOwner);
        vm.expectRevert();
        registry.mint(
            holder,
            "test-agent",
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );
    }

    function test_Seal_RevertWhenPaused() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.pause();

        vm.prank(contractOwner);
        vm.expectRevert();
        registry.seal(tokenId);
    }

    function test_Reseal_RevertWhenPaused() public {
        uint256 agentId = 12345;
        mockErc8004Registry.setOwner(agentId, contractOwner);

        uint256 tokenId = _mintWithErc8004("test-agent", agentId);

        vm.prank(contractOwner);
        registry.seal(tokenId);

        vm.prank(contractOwner);
        registry.pause();

        vm.prank(contractOwner);
        vm.expectRevert();
        registry.reseal(tokenId, bytes32(0), bytes32(0), bytes32(0), bytes32(0));
    }

    function test_Burn_RevertWhenPaused() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.pause();

        vm.prank(contractOwner);
        vm.expectRevert();
        registry.burn(tokenId, "test");
    }

    function test_VerifyOwner_RevertWhenPaused() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        vm.prank(contractOwner);
        registry.pause();

        vm.prank(contractOwner);
        vm.expectRevert();
        registry.verifyOwner(
            tokenId,
            address(mockVerifier),
            contractOwner,
            abi.encode(bytes32(uint256(1)), uint8(3))
        );
    }

    function test_Reincarnate_RevertWhenPaused() public {
        uint256 tokenId = _mintDefault("test-agent");

        vm.prank(contractOwner);
        registry.burn(tokenId, "test");

        vm.prank(contractOwner);
        registry.pause();

        vm.prank(contractOwner);
        vm.expectRevert();
        registry.reincarnate(
            tokenId,
            0,
            "new-agent",
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            arweaveTxId
        );
    }

    function test_Mint_WorksAfterUnpause() public {
        vm.prank(contractOwner);
        registry.pause();

        vm.prank(contractOwner);
        registry.unpause();

        vm.prank(contractOwner);
        uint256 tokenId = registry.mint(
            holder,
            "test-agent",
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            0,
            0,
            arweaveTxId,
            0,
            address(0),
            ""
        );

        assertTrue(tokenId > 0);
    }

    // ═══════════════════════════════════════════════════
    // Mint With Attestation Tests
    // ═══════════════════════════════════════════════════

    function test_MintWithAttestation_Success() public {
        // Add verifier
        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        // Mint with attestation
        vm.expectEmit(true, true, true, true);
        emit OwnerAttested(1, address(mockVerifier), 2, keccak256("mock-attestation"));

        uint256 tokenId = _mintWithAttestation("attested-agent", address(mockVerifier), "");

        // Verify attestation was set
        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.ownerAttestation.provider, address(mockVerifier));
        assertEq(record.ownerAttestation.trustTier, 2);
        assertEq(record.ownerAttestation.attestationId, keccak256("mock-attestation"));
        assertTrue(record.ownerAttestation.verifiedAt > 0);
    }

    function test_MintWithAttestation_NoVerifier() public {
        // Mint without attestation (verifier = address(0))
        uint256 tokenId = _mintDefault("no-attestation-agent");

        // Verify no attestation was set
        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.ownerAttestation.provider, address(0));
        assertEq(record.ownerAttestation.trustTier, 0);
        assertEq(record.ownerAttestation.attestationId, bytes32(0));
        assertEq(record.ownerAttestation.verifiedAt, 0);
    }

    function test_MintWithAttestation_RevertIfVerifierNotApproved() public {
        // Don't add verifier to approved list

        // Mint with unapproved verifier should revert (helper does vm.prank(contractOwner))
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.VerifierNotApproved.selector, address(mockVerifier)));
        _mintWithAttestation("attested-agent", address(mockVerifier), "");
    }

    function test_MintWithAttestation_RevertIfAgentSpawned() public {
        // Add verifier
        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        // Mint parent agent
        uint256 parentId = _mintDefault("parent-agent");

        // Mint child agent (agent-spawned) with attestation should revert
        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.AgentSpawnedCannotAttest.selector, 2));
        registry.mint(
            holder,
            "child-agent",
            soulHash,
            soulMerkleRoot,
            soulSalt,
            ChitinSoulRegistry.AgentType.Assistant,
            50,
            operator,
            liabilityAddress,
            parentId, // Has parent - agent-spawned
            0,
            arweaveTxId,
            0,
            address(mockVerifier), // Trying to attest
            ""
        );
    }

    function test_MintWithAttestation_CannotAttestAgain() public {
        // Add verifier
        vm.prank(contractOwner);
        registry.addVerifier(address(mockVerifier));

        // Mint with attestation (helper does vm.prank(contractOwner))
        uint256 tokenId = _mintWithAttestation("attested-agent", address(mockVerifier), "");

        // Try to attest again via verifyOwner should fail (record owner is contractOwner)
        vm.prank(contractOwner);
        vm.expectRevert(abi.encodeWithSelector(ChitinSoulRegistry.AlreadyAttested.selector, tokenId));
        registry.verifyOwner(tokenId, address(mockVerifier), contractOwner, "");
    }

    // ═══════════════════════════════════════════════════
    // Batch Chronicle Tests
    // ═══════════════════════════════════════════════════

    function test_RecordBatchChronicle_Success() public {
        bytes32 merkleRoot = keccak256("batch-merkle-root");
        bytes32 manifestTxId = keccak256("manifest-tx-id");
        uint64 count = 10;

        vm.prank(contractOwner);
        uint256 batchId = registry.recordBatchChronicle(merkleRoot, manifestTxId, count);

        assertEq(batchId, 0);
        assertEq(registry.getBatchCount(), 1);

        ChitinSoulRegistry.BatchRecord memory record = registry.getBatchRecord(0);
        assertEq(record.merkleRoot, merkleRoot);
        assertEq(record.manifestTxId, manifestTxId);
        assertEq(record.count, count);
        assertEq(record.timestamp, uint64(block.timestamp));
    }

    function test_RecordBatchChronicle_OnlyOwner() public {
        bytes32 merkleRoot = keccak256("batch-merkle-root");
        bytes32 manifestTxId = keccak256("manifest-tx-id");

        vm.prank(randomUser);
        vm.expectRevert();
        registry.recordBatchChronicle(merkleRoot, manifestTxId, 10);
    }

    function test_VerifyChronicleInBatch() public {
        // Build a small Merkle tree with 4 leaves
        bytes32 leaf0 = keccak256("chronicle-0");
        bytes32 leaf1 = keccak256("chronicle-1");
        bytes32 leaf2 = keccak256("chronicle-2");
        bytes32 leaf3 = keccak256("chronicle-3");

        // Build tree: hash pairs sorted
        bytes32 node01 = _hashPair(leaf0, leaf1);
        bytes32 node23 = _hashPair(leaf2, leaf3);
        bytes32 merkleRoot = _hashPair(node01, node23);

        // Record batch
        vm.prank(contractOwner);
        registry.recordBatchChronicle(merkleRoot, keccak256("manifest"), 4);

        // Verify leaf0 with proof [leaf1, node23]
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = leaf1;
        proof[1] = node23;

        assertTrue(registry.verifyChronicleInBatch(0, leaf0, proof));

        // Invalid leaf should fail
        bytes32 fakeLeaf = keccak256("fake");
        assertFalse(registry.verifyChronicleInBatch(0, fakeLeaf, proof));
    }

    function test_GetBatchCount() public {
        assertEq(registry.getBatchCount(), 0);

        vm.startPrank(contractOwner);
        registry.recordBatchChronicle(keccak256("root1"), keccak256("m1"), 5);
        registry.recordBatchChronicle(keccak256("root2"), keccak256("m2"), 3);
        registry.recordBatchChronicle(keccak256("root3"), keccak256("m3"), 7);
        vm.stopPrank();

        assertEq(registry.getBatchCount(), 3);
    }

    function test_GetBatchRecord_InvalidId() public {
        vm.expectRevert(ChitinSoulRegistry.InvalidBatchId.selector);
        registry.getBatchRecord(0);

        vm.prank(contractOwner);
        registry.recordBatchChronicle(keccak256("root"), keccak256("m"), 1);

        vm.expectRevert(ChitinSoulRegistry.InvalidBatchId.selector);
        registry.getBatchRecord(1);
    }

    // ═══════════════════════════════════════════════════
    // Self-Binding Prevention Tests
    // ═══════════════════════════════════════════════════

    function test_SetBinding_RevertIfSelfBinding() public {
        uint256 tokenId = _mintDefault("self-bind-agent");

        bytes32 contextHash = keccak256("self context");

        vm.prank(contractOwner);
        vm.expectRevert(ChitinSoulRegistry.SelfBindingNotAllowed.selector);
        registry.setBinding(tokenId, tokenId, ChitinSoulRegistry.TrustLevel.Verified, contextHash);
    }

    // ═══════════════════════════════════════════════════
    // AppendEvolution Return Value Tests
    // ═══════════════════════════════════════════════════

    function test_AppendEvolution_ReturnsEvolutionId() public {
        // Mint and seal
        uint256 tokenId = _mintDefault("evolution-return-agent");

        vm.prank(contractOwner);
        registry.seal(tokenId);

        // First evolution should return 0
        vm.prank(contractOwner);
        uint256 evolutionId0 = registry.appendEvolution(
            tokenId, ChitinSoulRegistry.ChangeType.Technical, keccak256("new soul 1"), arweaveTxId
        );
        assertEq(evolutionId0, 0, "First evolution ID should be 0");

        // Second evolution should return 1
        vm.prank(contractOwner);
        uint256 evolutionId1 = registry.appendEvolution(
            tokenId, ChitinSoulRegistry.ChangeType.Achievement, keccak256("new soul 2"), arweaveTxId
        );
        assertEq(evolutionId1, 1, "Second evolution ID should be 1");

        // Third evolution should return 2
        vm.prank(contractOwner);
        uint256 evolutionId2 = registry.appendEvolution(
            tokenId, ChitinSoulRegistry.ChangeType.Certification, bytes32(0), arweaveTxId
        );
        assertEq(evolutionId2, 2, "Third evolution ID should be 2");
    }

    // ═══════════════════════════════════════════════════
    // GetBinding Pair Search Tests
    // ═══════════════════════════════════════════════════

    function test_GetBinding_Found() public {
        uint256 tokenId1 = _mintDefault("bind-from-agent");
        uint256 tokenId2 = _mintDefault("bind-to-agent");

        bytes32 contextHash = keccak256("collaboration context");

        vm.prank(contractOwner);
        registry.setBinding(tokenId1, tokenId2, ChitinSoulRegistry.TrustLevel.Trusted, contextHash);

        (ChitinSoulRegistry.AgentBinding memory binding, bool found) = registry.getBinding(tokenId1, tokenId2);

        assertTrue(found, "Binding should be found");
        assertEq(binding.fromTokenId, tokenId1);
        assertEq(binding.toTokenId, tokenId2);
        assertEq(uint8(binding.trustLevel), uint8(ChitinSoulRegistry.TrustLevel.Trusted));
        assertEq(binding.contextHash, contextHash);
    }

    function test_GetBinding_NotFound() public {
        uint256 tokenId1 = _mintDefault("no-bind-from");
        uint256 tokenId2 = _mintDefault("no-bind-to");

        (ChitinSoulRegistry.AgentBinding memory binding, bool found) = registry.getBinding(tokenId1, tokenId2);

        assertFalse(found, "Binding should not be found");
        assertEq(binding.fromTokenId, 0);
        assertEq(binding.toTokenId, 0);
    }

    function test_GetBinding_MultipleBindings() public {
        uint256 tokenId1 = _mintDefault("multi-bind-from");
        uint256 tokenId2 = _mintDefault("multi-bind-to-a");
        uint256 tokenId3 = _mintDefault("multi-bind-to-b");

        bytes32 contextHash2 = keccak256("context with agent 2");
        bytes32 contextHash3 = keccak256("context with agent 3");

        vm.startPrank(contractOwner);
        registry.setBinding(tokenId1, tokenId2, ChitinSoulRegistry.TrustLevel.Verified, contextHash2);
        registry.setBinding(tokenId1, tokenId3, ChitinSoulRegistry.TrustLevel.Trusted, contextHash3);
        vm.stopPrank();

        // Search for binding to tokenId3
        (ChitinSoulRegistry.AgentBinding memory binding3, bool found3) = registry.getBinding(tokenId1, tokenId3);
        assertTrue(found3, "Binding to tokenId3 should be found");
        assertEq(binding3.toTokenId, tokenId3);
        assertEq(uint8(binding3.trustLevel), uint8(ChitinSoulRegistry.TrustLevel.Trusted));
        assertEq(binding3.contextHash, contextHash3);

        // Search for binding to tokenId2
        (ChitinSoulRegistry.AgentBinding memory binding2, bool found2) = registry.getBinding(tokenId1, tokenId2);
        assertTrue(found2, "Binding to tokenId2 should be found");
        assertEq(binding2.toTokenId, tokenId2);
        assertEq(uint8(binding2.trustLevel), uint8(ChitinSoulRegistry.TrustLevel.Verified));
    }

    /// @dev Helper: hash pair using OpenZeppelin's MerkleProof convention (sorted)
    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b
            ? keccak256(abi.encodePacked(a, b))
            : keccak256(abi.encodePacked(b, a));
    }
}

