// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {CrossChainVerifier} from "../src/CrossChainVerifier.sol";

contract DeployCrossChainVerifier is Script {
    function run() public returns (address verifierContract) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.envAddress("OWNER_ADDRESS");

        // Verifier address (the address that signs cross-chain proofs)
        // This should be the address derived from CROSS_CHAIN_VERIFIER_PRIVATE_KEY
        address verifier = vm.envAddress("CROSS_CHAIN_VERIFIER_ADDRESS");

        console.log("Deploying CrossChainVerifier...");
        console.log("Owner:", owner);
        console.log("Verifier:", verifier);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy CrossChainVerifier
        verifierContract = address(new CrossChainVerifier(owner, verifier));
        console.log("CrossChainVerifier deployed at:", verifierContract);

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("CrossChainVerifier:", verifierContract);
        console.log("Owner:", owner);
        console.log("Verifier:", verifier);
        console.log("Signature Expiry: 300 seconds (5 minutes)");
    }
}
