// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/validators/ChitinValidator.sol";
import "../src/ChitinSoulRegistry.sol";
import "../src/mocks/MockERC8004Registry.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract ChitinValidatorTest is Test {
    ChitinSoulRegistry public registry;
    ChitinSoulRegistry public registryImpl;
    ChitinValidator public validator;
    MockERC8004Registry public erc8004Registry;

    address public owner = address(0x1);
    address public operator = address(0x2);
    address public holder = address(0x3);
    address public attacker = address(0x4);

    uint256 public tokenId;

    // Default soul parameters
    bytes32 constant SOUL_HASH = keccak256("test-soul-hash");
    bytes32 constant SOUL_MERKLE_ROOT = keccak256("test-merkle-root");
    bytes32 constant SOUL_SALT = keccak256("test-salt");
    bytes32 constant ARWEAVE_TX_ID = keccak256("test-arweave-tx");

    function setUp() public {
        // Deploy mock ERC-8004 registry
        erc8004Registry = new MockERC8004Registry();

        // Deploy registry implementation
        registryImpl = new ChitinSoulRegistry();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            ChitinSoulRegistry.initialize.selector,
            owner,
            address(erc8004Registry)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(registryImpl), initData);
        registry = ChitinSoulRegistry(address(proxy));

        // Deploy validator
        validator = new ChitinValidator(address(registry));

        // Set validator in registry
        vm.prank(owner);
        registry.setChitinValidator(address(validator));

        // Mint a test token
        vm.prank(owner);
        tokenId = registry.mint(
            holder,
            "test-agent",
            SOUL_HASH,
            SOUL_MERKLE_ROOT,
            SOUL_SALT,
            ChitinSoulRegistry.AgentType.Specialist,
            50,
            operator,
            owner,
            0,
            0,
            ARWEAVE_TX_ID,
            0,
            address(0),
            ""
        );

        // Seal the token
        vm.prank(owner);
        registry.seal(tokenId);
    }

    // ═══════════════════════════════════════════════════
    // Permission Check Tests
    // ═══════════════════════════════════════════════════

    function test_CheckPermission_AgentSolo_Owner() public view {
        bool allowed = validator.checkPermission(
            tokenId,
            owner,
            IChitinValidator.PermissionLevel.AgentSolo
        );
        assertTrue(allowed);
    }

    function test_CheckPermission_AgentSolo_Operator() public view {
        bool allowed = validator.checkPermission(
            tokenId,
            operator,
            IChitinValidator.PermissionLevel.AgentSolo
        );
        assertTrue(allowed);
    }

    function test_CheckPermission_AgentSolo_Attacker() public view {
        bool allowed = validator.checkPermission(
            tokenId,
            attacker,
            IChitinValidator.PermissionLevel.AgentSolo
        );
        assertFalse(allowed);
    }

    function test_CheckPermission_OwnerOnly_Owner() public view {
        bool allowed = validator.checkPermission(
            tokenId,
            owner,
            IChitinValidator.PermissionLevel.OwnerOnly
        );
        assertTrue(allowed);
    }

    function test_CheckPermission_OwnerOnly_Operator() public view {
        bool allowed = validator.checkPermission(
            tokenId,
            operator,
            IChitinValidator.PermissionLevel.OwnerOnly
        );
        assertFalse(allowed);
    }

    // ═══════════════════════════════════════════════════
    // Freeze Tests
    // ═══════════════════════════════════════════════════

    function test_Freeze_Success() public {
        vm.prank(owner);
        validator.freeze(tokenId);

        assertTrue(validator.isFrozen(tokenId));
    }

    function test_Freeze_OnlyOwner() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinValidator.NotOwner.selector,
                tokenId,
                operator
            )
        );
        validator.freeze(tokenId);
    }

    function test_Freeze_AlreadyFrozen() public {
        vm.prank(owner);
        validator.freeze(tokenId);

        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinValidator.AlreadyFrozen.selector,
                tokenId
            )
        );
        validator.freeze(tokenId);
    }

    function test_Unfreeze_Success() public {
        vm.prank(owner);
        validator.freeze(tokenId);

        vm.prank(owner);
        validator.unfreeze(tokenId);

        assertFalse(validator.isFrozen(tokenId));
    }

    function test_Unfreeze_NotFrozen() public {
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinValidator.NotFrozen.selector,
                tokenId
            )
        );
        validator.unfreeze(tokenId);
    }

    function test_Freeze_BlocksPermissions() public {
        vm.prank(owner);
        validator.freeze(tokenId);

        bool allowed = validator.checkPermission(
            tokenId,
            owner,
            IChitinValidator.PermissionLevel.AgentSolo
        );
        assertFalse(allowed);
    }

    // ═══════════════════════════════════════════════════
    // Dual Signature Tests
    // ═══════════════════════════════════════════════════

    function test_DualSignature_InitiateByOwner() public {
        bytes32 opHash = keccak256("test-operation");

        validator.initiateDualSignature(tokenId, opHash, owner);

        ChitinValidator.PendingOperation memory pending = validator.getPendingOperation(tokenId, opHash);
        assertEq(pending.initiator, owner);
        assertTrue(pending.ownerSigned);
        assertFalse(pending.operatorSigned);
    }

    function test_DualSignature_InitiateByOperator() public {
        bytes32 opHash = keccak256("test-operation");

        validator.initiateDualSignature(tokenId, opHash, operator);

        ChitinValidator.PendingOperation memory pending = validator.getPendingOperation(tokenId, opHash);
        assertEq(pending.initiator, operator);
        assertFalse(pending.ownerSigned);
        assertTrue(pending.operatorSigned);
    }

    function test_DualSignature_Complete() public {
        bytes32 opHash = keccak256("test-operation");

        // Owner initiates
        validator.initiateDualSignature(tokenId, opHash, owner);

        // Operator confirms
        bool complete = validator.confirmDualSignature(tokenId, opHash, operator);
        assertTrue(complete);

        ChitinValidator.PendingOperation memory pending = validator.getPendingOperation(tokenId, opHash);
        assertTrue(pending.executed);
    }

    function test_DualSignature_NotAuthorized() public {
        bytes32 opHash = keccak256("test-operation");

        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinValidator.NotOwnerOrOperator.selector,
                tokenId,
                attacker
            )
        );
        validator.initiateDualSignature(tokenId, opHash, attacker);
    }

    function test_DualSignature_Cancel() public {
        bytes32 opHash = keccak256("test-operation");

        validator.initiateDualSignature(tokenId, opHash, owner);

        vm.prank(owner);
        validator.cancelDualSignature(tokenId, opHash);

        ChitinValidator.PendingOperation memory pending = validator.getPendingOperation(tokenId, opHash);
        assertEq(pending.initiatedAt, 0); // Deleted
    }

    function test_DualSignature_Expiry() public {
        bytes32 opHash = keccak256("test-operation");

        validator.initiateDualSignature(tokenId, opHash, owner);

        // Warp past expiry
        vm.warp(block.timestamp + 25 hours);

        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinValidator.OperationExpired.selector,
                tokenId,
                opHash
            )
        );
        validator.confirmDualSignature(tokenId, opHash, operator);
    }

    // ═══════════════════════════════════════════════════
    // Registry Integration Tests
    // ═══════════════════════════════════════════════════

    function test_Registry_FrozenBlocksEvolution() public {
        // Freeze the agent
        vm.prank(owner);
        validator.freeze(tokenId);

        // Try to append evolution - should fail
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinSoulRegistry.AgentFrozen.selector,
                tokenId
            )
        );
        registry.appendEvolution(
            tokenId,
            ChitinSoulRegistry.ChangeType.Technical,
            keccak256("new-soul"),
            keccak256("arweave-tx")
        );
    }

    function test_Registry_FrozenBlocksBurn() public {
        // Freeze the agent
        vm.prank(owner);
        validator.freeze(tokenId);

        // Try to burn - should fail
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinSoulRegistry.AgentFrozen.selector,
                tokenId
            )
        );
        registry.burn(tokenId, "test");
    }

    function test_Registry_SetOperator() public {
        address newOperator = address(0x5);

        vm.prank(owner);
        registry.setOperator(tokenId, newOperator);

        ChitinSoulRegistry.GenesisRecord memory record = registry.getGenesisRecord(tokenId);
        assertEq(record.operator, newOperator);
    }

    function test_Registry_SetOperator_CannotBeSameAsOwner() public {
        vm.prank(owner);
        vm.expectRevert(ChitinSoulRegistry.OperatorCannotBeSameAsOwner.selector);
        registry.setOperator(tokenId, owner);
    }

    function test_Registry_SetOperator_OnlyOwner() public {
        address newOperator = address(0x5);

        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                ChitinSoulRegistry.OnlyOwnerCanBurn.selector,
                tokenId
            )
        );
        registry.setOperator(tokenId, newOperator);
    }

    // ═══════════════════════════════════════════════════
    // Helper Function Tests
    // ═══════════════════════════════════════════════════

    function test_IsOwner() public view {
        assertTrue(validator.isOwner(tokenId, owner));
        assertFalse(validator.isOwner(tokenId, operator));
    }

    function test_IsOperator() public view {
        assertTrue(validator.isOperator(tokenId, operator));
        assertFalse(validator.isOperator(tokenId, owner));
    }

    function test_IsOwnerOrOperator() public view {
        assertTrue(validator.isOwnerOrOperator(tokenId, owner));
        assertTrue(validator.isOwnerOrOperator(tokenId, operator));
        assertFalse(validator.isOwnerOrOperator(tokenId, attacker));
    }

    function test_GenerateOperationHash() public {
        bytes32 hash1 = validator.generateOperationHash(tokenId, "setOperator", "");
        bytes32 hash2 = validator.generateOperationHash(tokenId, "setOperator", "");

        // Each call should generate a unique hash due to nonce
        assertNotEq(hash1, hash2);
    }

    // ═══════════════════════════════════════════════════
    // Event Tests
    // ═══════════════════════════════════════════════════

    function test_Event_AgentFrozen() public {
        vm.expectEmit(true, true, false, true);
        emit ChitinValidator.AgentFrozen(tokenId, owner, uint64(block.timestamp));

        vm.prank(owner);
        validator.freeze(tokenId);
    }

    function test_Event_AgentUnfrozen() public {
        vm.prank(owner);
        validator.freeze(tokenId);

        vm.expectEmit(true, true, false, false);
        emit ChitinValidator.AgentUnfrozen(tokenId, owner);

        vm.prank(owner);
        validator.unfreeze(tokenId);
    }

    function test_Event_DualSignatureInitiated() public {
        bytes32 opHash = keccak256("test-operation");

        vm.expectEmit(true, true, true, true);
        emit ChitinValidator.DualSignatureInitiated(
            tokenId,
            opHash,
            owner,
            uint64(block.timestamp + 24 hours)
        );

        validator.initiateDualSignature(tokenId, opHash, owner);
    }

    function test_Event_OperatorChanged() public {
        address newOperator = address(0x5);

        vm.expectEmit(true, true, true, false);
        emit ChitinSoulRegistry.OperatorChanged(tokenId, operator, newOperator);

        vm.prank(owner);
        registry.setOperator(tokenId, newOperator);
    }
}

