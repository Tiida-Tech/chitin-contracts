// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {WorldIdVerifier} from "../src/verifiers/WorldIdVerifier.sol";
import {ChitinSoulRegistry} from "../src/ChitinSoulRegistry.sol";

/// @title DeployWorldIdVerifier
/// @notice Deploy WorldIdVerifier adapter and register it in ChitinSoulRegistry
/// @dev Environment variables:
///   PRIVATE_KEY          - Deployer's private key (required)
///   WORLD_ID_ROUTER      - World ID router address (required)
///   WORLD_ID_APP_ID      - World ID app ID as bytes32 (required)
///   CHITIN_REGISTRY      - ChitinSoulRegistry proxy address (required)
///
/// Default testnet values (Base Sepolia):
///   WORLD_ID_ROUTER = 0x42FF98C4E85212a5D31358ACbFe76a621b50fC02
///   CHITIN_REGISTRY = 0x716c88b271225f44e437562D7B2799265d810294
contract DeployWorldIdVerifier is Script {
    // Default values for Base Sepolia (can be overridden via env vars)
    address constant DEFAULT_WORLD_ID_ROUTER_SEPOLIA = 0x42FF98C4E85212a5D31358ACbFe76a621b50fC02;
    address constant DEFAULT_CHITIN_REGISTRY_SEPOLIA = 0x716c88b271225f44e437562D7B2799265d810294;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        // Get World ID Router (use env var or default to Base Sepolia)
        address worldIdRouter = vm.envOr("WORLD_ID_ROUTER", DEFAULT_WORLD_ID_ROUTER_SEPOLIA);

        // Get App ID (required - no good default)
        bytes32 appId = vm.envOr("WORLD_ID_APP_ID", bytes32("app_chitin_soul_verify"));

        // Get Chitin Registry (use env var or default to Base Sepolia)
        address chitinRegistry = vm.envOr("CHITIN_REGISTRY", DEFAULT_CHITIN_REGISTRY_SEPOLIA);

        console.log("Deployer:", deployer);
        console.log("World ID Router:", worldIdRouter);
        console.log("Chitin Registry:", chitinRegistry);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy WorldIdVerifier
        WorldIdVerifier verifier = new WorldIdVerifier(
            worldIdRouter,
            appId
        );
        console.log("WorldIdVerifier deployed:", address(verifier));

        // Register in ChitinSoulRegistry
        ChitinSoulRegistry registry = ChitinSoulRegistry(chitinRegistry);
        registry.addVerifier(address(verifier));
        console.log("Verifier registered in ChitinSoulRegistry");

        // Verify registration
        bool isApproved = registry.isApprovedVerifier(address(verifier));
        console.log("Is approved verifier:", isApproved);

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("WorldIdVerifier:", address(verifier));
        console.log("Registered in Registry:", isApproved ? "Yes" : "No");
    }
}
