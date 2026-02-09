// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TrustedWorldIdVerifier} from "../src/verifiers/TrustedWorldIdVerifier.sol";

/// @title DeployTrustedWorldIdVerifier
/// @notice Deploy TrustedWorldIdVerifier for Base Mainnet (Phase 1: API-verified)
/// @dev Environment variables:
///   PRIVATE_KEY     - Deployer's private key
///   REGISTRY_ADDRESS - ChitinSoulRegistry proxy address (to approve verifier)
contract DeployTrustedWorldIdVerifier is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("=== Deploy TrustedWorldIdVerifier ===");
        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);

        TrustedWorldIdVerifier verifier = new TrustedWorldIdVerifier();
        console.log("TrustedWorldIdVerifier deployed:", address(verifier));

        vm.stopBroadcast();

        console.log("");
        console.log("=== Next Steps ===");
        console.log("1. Approve verifier on ChitinSoulRegistry:");
        console.log("   cast send $REGISTRY setApprovedVerifier(address,bool) ", address(verifier), " true");
        console.log("2. Update NEXT_PUBLIC_WORLD_ID_VERIFIER env var to:", address(verifier));
    }
}
