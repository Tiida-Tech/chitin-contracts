// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {MockERC8004Registry} from "../src/mocks/MockERC8004Registry.sol";

contract DeployMockERC8004 is Script {
    function run() public returns (address registry) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        registry = address(new MockERC8004Registry());
        console.log("MockERC8004Registry deployed at:", registry);

        vm.stopBroadcast();

        return registry;
    }
}
