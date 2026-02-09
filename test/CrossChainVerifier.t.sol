// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {CrossChainVerifier} from "../src/CrossChainVerifier.sol";

contract CrossChainVerifierTest is Test {
    CrossChainVerifier public verifier;

    address public owner = address(0x1);
    address public verifierSigner;
    uint256 public verifierPrivateKey;

    address public user = address(0x3);

    // Test data
    uint256 constant SOURCE_AGENT_ID = 123;
    uint256 constant SOURCE_CHAIN_ID = 137; // Polygon

    function setUp() public {
        // Create verifier signer
        verifierPrivateKey = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
        verifierSigner = vm.addr(verifierPrivateKey);

        // Deploy verifier contract
        vm.prank(owner);
        verifier = new CrossChainVerifier(owner, verifierSigner);
    }

    // ═══════════════════════════════════════════════════
    // Helper Functions
    // ═══════════════════════════════════════════════════

    function _createProof(
        uint256 agentId,
        uint256 chainId,
        address proofOwner,
        uint256 timestamp,
        bytes32 nonce
    ) internal view returns (CrossChainVerifier.CrossChainProof memory) {
        // Create message hash
        bytes32 messageHash = keccak256(
            abi.encodePacked(agentId, chainId, proofOwner, timestamp, nonce)
        );

        // Sign with verifier private key (EIP-191)
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifierPrivateKey, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        return CrossChainVerifier.CrossChainProof({
            agentId: agentId,
            chainId: chainId,
            owner: proofOwner,
            timestamp: timestamp,
            nonce: nonce,
            signature: signature
        });
    }

    function _createValidProof() internal view returns (CrossChainVerifier.CrossChainProof memory) {
        return _createProof(
            SOURCE_AGENT_ID,
            SOURCE_CHAIN_ID,
            user,
            block.timestamp,
            keccak256("test-nonce-1")
        );
    }

    // ═══════════════════════════════════════════════════
    // Deployment Tests
    // ═══════════════════════════════════════════════════

    function test_Deployment() public view {
        assertEq(verifier.owner(), owner);
        assertEq(verifier.verifier(), verifierSigner);
        assertEq(verifier.signatureExpiry(), 300);
    }

    function test_Deployment_RevertZeroVerifier() public {
        vm.prank(owner);
        vm.expectRevert(CrossChainVerifier.ZeroAddress.selector);
        new CrossChainVerifier(owner, address(0));
    }

    // ═══════════════════════════════════════════════════
    // Verification Tests
    // ═══════════════════════════════════════════════════

    function test_VerifyProof_Valid() public view {
        CrossChainVerifier.CrossChainProof memory proof = _createValidProof();
        assertTrue(verifier.verifyProof(proof));
    }

    function test_VerifyProof_InvalidSignature() public view {
        CrossChainVerifier.CrossChainProof memory proof = _createValidProof();
        // Corrupt signature
        proof.signature[0] = bytes1(uint8(proof.signature[0]) ^ 0xff);
        assertFalse(verifier.verifyProof(proof));
    }

    function test_VerifyProof_Expired() public {
        // Create proof with old timestamp
        vm.warp(1000);
        CrossChainVerifier.CrossChainProof memory proof = _createProof(
            SOURCE_AGENT_ID,
            SOURCE_CHAIN_ID,
            user,
            100, // Old timestamp
            keccak256("test-nonce-2")
        );

        // Warp to future (beyond expiry)
        vm.warp(500); // 400 seconds after proof timestamp, but expiry is 300
        assertFalse(verifier.verifyProof(proof));
    }

    function test_VerifyProof_WrongSigner() public {
        // Create proof signed by different key
        uint256 wrongKey = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
        address wrongSigner = vm.addr(wrongKey);

        bytes32 messageHash = keccak256(
            abi.encodePacked(SOURCE_AGENT_ID, SOURCE_CHAIN_ID, user, block.timestamp, keccak256("test-nonce-3"))
        );
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        CrossChainVerifier.CrossChainProof memory proof = CrossChainVerifier.CrossChainProof({
            agentId: SOURCE_AGENT_ID,
            chainId: SOURCE_CHAIN_ID,
            owner: user,
            timestamp: block.timestamp,
            nonce: keccak256("test-nonce-3"),
            signature: signature
        });

        assertFalse(verifier.verifyProof(proof));
    }

    // ═══════════════════════════════════════════════════
    // Consume Tests
    // ═══════════════════════════════════════════════════

    function test_VerifyAndConsumeProof_Success() public {
        CrossChainVerifier.CrossChainProof memory proof = _createValidProof();

        vm.expectEmit(true, true, true, true);
        emit CrossChainVerifier.ProofVerified(
            proof.agentId,
            proof.chainId,
            proof.owner,
            proof.nonce
        );

        bool result = verifier.verifyAndConsumeProof(proof);
        assertTrue(result);
        assertTrue(verifier.isNonceUsed(proof.nonce));
    }

    function test_VerifyAndConsumeProof_RevertNonceReuse() public {
        CrossChainVerifier.CrossChainProof memory proof = _createValidProof();

        // First use should succeed
        verifier.verifyAndConsumeProof(proof);

        // Second use should fail
        vm.expectRevert(abi.encodeWithSelector(CrossChainVerifier.NonceAlreadyUsed.selector, proof.nonce));
        verifier.verifyAndConsumeProof(proof);
    }

    function test_VerifyAndConsumeProof_RevertExpired() public {
        vm.warp(1000);
        CrossChainVerifier.CrossChainProof memory proof = _createProof(
            SOURCE_AGENT_ID,
            SOURCE_CHAIN_ID,
            user,
            100, // Old timestamp
            keccak256("test-nonce-4")
        );

        vm.warp(500);
        vm.expectRevert(abi.encodeWithSelector(CrossChainVerifier.SignatureExpired.selector, 100, 500));
        verifier.verifyAndConsumeProof(proof);
    }

    function test_VerifyAndConsumeProof_RevertInvalidSignature() public {
        CrossChainVerifier.CrossChainProof memory proof = _createValidProof();
        proof.signature[0] = bytes1(uint8(proof.signature[0]) ^ 0xff);

        vm.expectRevert(CrossChainVerifier.InvalidSignature.selector);
        verifier.verifyAndConsumeProof(proof);
    }

    // ═══════════════════════════════════════════════════
    // Admin Tests
    // ═══════════════════════════════════════════════════

    function test_SetVerifier() public {
        address newVerifier = address(0x999);

        vm.prank(owner);
        vm.expectEmit(true, true, false, true);
        emit CrossChainVerifier.VerifierUpdated(verifierSigner, newVerifier);
        verifier.setVerifier(newVerifier);

        assertEq(verifier.verifier(), newVerifier);
    }

    function test_SetVerifier_RevertNotOwner() public {
        vm.prank(user);
        vm.expectRevert();
        verifier.setVerifier(address(0x999));
    }

    function test_SetVerifier_RevertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(CrossChainVerifier.ZeroAddress.selector);
        verifier.setVerifier(address(0));
    }

    function test_SetSignatureExpiry() public {
        uint256 newExpiry = 600;

        vm.prank(owner);
        vm.expectEmit(false, false, false, true);
        emit CrossChainVerifier.SignatureExpiryUpdated(300, newExpiry);
        verifier.setSignatureExpiry(newExpiry);

        assertEq(verifier.signatureExpiry(), newExpiry);
    }

    // ═══════════════════════════════════════════════════
    // Helper Function Tests
    // ═══════════════════════════════════════════════════

    function test_GetMessageHash() public view {
        bytes32 expected = keccak256(
            abi.encodePacked(
                uint256(123),
                uint256(137),
                user,
                uint256(1000),
                bytes32(keccak256("nonce"))
            )
        );

        bytes32 actual = verifier.getMessageHash(
            123,
            137,
            user,
            1000,
            keccak256("nonce")
        );

        assertEq(actual, expected);
    }

    // ═══════════════════════════════════════════════════
    // Fuzz Tests
    // ═══════════════════════════════════════════════════

    function testFuzz_VerifyProof_DifferentData(
        uint256 agentId,
        uint256 chainId,
        address proofOwner
    ) public {
        vm.assume(proofOwner != address(0));

        CrossChainVerifier.CrossChainProof memory proof = _createProof(
            agentId,
            chainId,
            proofOwner,
            block.timestamp,
            keccak256(abi.encodePacked(agentId, chainId, proofOwner))
        );

        assertTrue(verifier.verifyProof(proof));
    }
}
