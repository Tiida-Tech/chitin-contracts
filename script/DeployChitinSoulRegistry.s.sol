// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ChitinSoulRegistry} from "../src/ChitinSoulRegistry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployChitinSoulRegistry is Script {
    function run() public returns (address proxy, address implementation) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address owner = vm.envAddress("OWNER_ADDRESS");

        // ERC-8004 Registry address (required for full ecosystem, can be address(0) initially and set later)
        address erc8004Registry = vm.envOr("ERC8004_REGISTRY", address(0));

        vm.startBroadcast(deployerPrivateKey);

        // Note: TokenURILib will be deployed and linked automatically by Foundry

        // Deploy implementation
        implementation = address(new ChitinSoulRegistry());
        console.log("Implementation deployed at:", implementation);

        // Deploy proxy with ERC-8004 registry parameter
        bytes memory initData = abi.encodeWithSelector(
            ChitinSoulRegistry.initialize.selector,
            owner,
            erc8004Registry
        );

        proxy = address(new ERC1967Proxy(implementation, initData));
        console.log("Proxy deployed at:", proxy);
        console.log("Owner set to:", owner);
        console.log("ERC-8004 Registry:", erc8004Registry);

        vm.stopBroadcast();

        return (proxy, implementation);
    }
}
