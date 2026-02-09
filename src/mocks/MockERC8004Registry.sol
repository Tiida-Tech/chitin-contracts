// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title MockERC8004Registry
 * @notice Simple mock for testing ERC-8004 Agent Passport integration
 * @dev Implements minimal ownerOf(agentId) for ChitinSoulRegistry integration
 */
contract MockERC8004Registry {
    // agentId => owner
    mapping(uint256 => address) private _owners;

    // Counter for minting new agent passports
    uint256 private _nextAgentId = 1;

    event AgentPassportMinted(uint256 indexed agentId, address indexed owner);
    event AgentPassportTransferred(uint256 indexed agentId, address indexed from, address indexed to);

    /**
     * @notice Mint a new agent passport
     * @param to The owner of the new passport
     * @return agentId The ID of the newly minted passport
     */
    function mint(address to) external returns (uint256 agentId) {
        require(to != address(0), "Invalid owner");
        agentId = _nextAgentId++;
        _owners[agentId] = to;
        emit AgentPassportMinted(agentId, to);
    }

    /**
     * @notice Get the owner of an agent passport
     * @param agentId The agent passport ID
     * @return The owner address
     */
    function ownerOf(uint256 agentId) external view returns (address) {
        address owner = _owners[agentId];
        require(owner != address(0), "Agent passport does not exist");
        return owner;
    }

    /**
     * @notice Transfer an agent passport (for testing passport ownership changes)
     * @param agentId The agent passport ID
     * @param to The new owner
     */
    function transfer(uint256 agentId, address to) external {
        require(to != address(0), "Invalid recipient");
        address from = _owners[agentId];
        require(from != address(0), "Agent passport does not exist");
        require(msg.sender == from, "Not the owner");
        _owners[agentId] = to;
        emit AgentPassportTransferred(agentId, from, to);
    }

    /**
     * @notice Check if an agent passport exists
     * @param agentId The agent passport ID
     * @return True if exists
     */
    function exists(uint256 agentId) external view returns (bool) {
        return _owners[agentId] != address(0);
    }

    /**
     * @notice Get the next agent ID that will be minted
     */
    function nextAgentId() external view returns (uint256) {
        return _nextAgentId;
    }
}
