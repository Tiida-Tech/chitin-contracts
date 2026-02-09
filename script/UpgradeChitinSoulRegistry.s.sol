// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ChitinSoulRegistry} from "../src/ChitinSoulRegistry.sol";

/// @title UpgradeChitinSoulRegistry
/// @notice Upgrade ChitinSoulRegistry to a new implementation via UUPS proxy
/// @dev Environment variables:
///   PRIVATE_KEY     - Owner's private key (must be contract owner)
///   PROXY_ADDRESS   - ChitinSoulRegistry proxy address
///
/// Usage:
///   forge script script/UpgradeChitinSoulRegistry.s.sol --rpc-url $RPC_URL --broadcast --verify
contract UpgradeChitinSoulRegistry is Script {
    function run() public {
        uint256 ownerPrivateKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.addr(ownerPrivateKey);
        address proxyAddress = vm.envAddress("PROXY_ADDRESS");

        console.log("=== ChitinSoulRegistry Upgrade ===");
        console.log("Owner:", owner);
        console.log("Proxy:", proxyAddress);
        console.log("Chain ID:", block.chainid);
        console.log("");

        // Get current implementation
        ChitinSoulRegistry proxy = ChitinSoulRegistry(proxyAddress);

        // Verify owner
        require(proxy.owner() == owner, "Caller is not the owner");
        console.log("Owner verified");

        vm.startBroadcast(ownerPrivateKey);

        // Deploy new implementation
        ChitinSoulRegistry newImplementation = new ChitinSoulRegistry();
        console.log("New implementation deployed:", address(newImplementation));

        // Upgrade proxy to new implementation
        proxy.upgradeToAndCall(address(newImplementation), "");
        console.log("Proxy upgraded to new implementation");

        vm.stopBroadcast();

        // Print summary
        console.log("");
        console.log("=== Upgrade Summary ===");
        console.log("Proxy (unchanged):", proxyAddress);
        console.log("New Implementation:", address(newImplementation));
        console.log("");
        console.log("=== Next Steps ===");
        console.log("1. Verify new implementation on Basescan:");
        console.log("   forge verify-contract", address(newImplementation), "ChitinSoulRegistry --chain base");
        console.log("");
        console.log("2. Test that existing data is preserved");
        console.log("3. Test new functionality (mint with attestation)");
    }
}

/// @title UpgradeChitinSoulRegistryDryRun
/// @notice Dry run to validate upgrade configuration
contract UpgradeChitinSoulRegistryDryRun is Script {
    function run() public view {
        console.log("=== Upgrade Dry Run ===");
        console.log("");

        bool hasErrors = false;

        // Check PRIVATE_KEY
        try vm.envUint("PRIVATE_KEY") returns (uint256 pk) {
            address owner = vm.addr(pk);
            console.log("[OK] PRIVATE_KEY set, owner:", owner);
        } catch {
            console.log("[ERROR] PRIVATE_KEY not set or invalid");
            hasErrors = true;
        }

        // Check PROXY_ADDRESS
        try vm.envAddress("PROXY_ADDRESS") returns (address proxy) {
            console.log("[OK] PROXY_ADDRESS:", proxy);
        } catch {
            console.log("[ERROR] PROXY_ADDRESS not set or invalid");
            hasErrors = true;
        }

        console.log("");
        if (hasErrors) {
            console.log("=== DRY RUN FAILED ===");
        } else {
            console.log("=== DRY RUN PASSED ===");
            console.log("");
            console.log("To upgrade, run:");
            console.log("  forge script script/UpgradeChitinSoulRegistry.s.sol --rpc-url $RPC_URL --broadcast --verify");
        }
    }
}
