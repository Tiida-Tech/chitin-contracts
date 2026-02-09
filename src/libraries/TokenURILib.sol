// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

/// @title TokenURILib
/// @notice Library for generating Chitin SBT token URIs
/// @dev Separated to reduce ChitinSoulRegistry contract size
library TokenURILib {
    using Strings for uint256;

    /// @notice Generate the complete tokenURI for a Chitin SBT
    /// @param tokenId The token ID
    /// @param name The agent name
    /// @return The data URI containing JSON metadata with embedded SVG
    function generateTokenURI(uint256 tokenId, string memory name) external pure returns (string memory) {
        string memory idStr = tokenId.toString();
        string memory svg = _generateSVG(tokenId, name, idStr);
        return _generateJSON(name, idStr, svg);
    }

    /// @notice Generate the SVG image for a Chitin SBT
    function _generateSVG(uint256, string memory name, string memory idStr) private pure returns (string memory) {
        // Dynamic font sizing based on name length
        uint256 nameLen = bytes(name).length;
        string memory nameFontSize;
        string memory didFontSize;
        string memory didY;

        if (nameLen <= 10) {
            nameFontSize = "52";
            didFontSize = "12";
            didY = "241";
        } else if (nameLen <= 16) {
            nameFontSize = "38";
            didFontSize = "10";
            didY = "232";
        } else if (nameLen <= 24) {
            nameFontSize = "28";
            didFontSize = "9";
            didY = "225";
        } else {
            nameFontSize = "22";
            didFontSize = "8";
            didY = "220";
        }

        // Build SVG (split to avoid stack-too-deep)
        string memory svg = string(abi.encodePacked(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400">',
            '<rect width="400" height="400" fill="#F5F0E8"/>',
            '<text x="200" y="48" text-anchor="middle" font-family="monospace" font-size="10" letter-spacing="0.25em" fill="#8A8A8A">CHITIN GENESIS RECORD</text>',
            '<text x="200" y="64" text-anchor="middle" font-family="monospace" font-size="8" letter-spacing="0.15em" fill="#AEAAA0">SOULBOUND TOKEN</text>',
            '<line x1="80" y1="78" x2="320" y2="78" stroke="#E8E0D0" stroke-width="1"/>',
            '<text x="200" y="106" text-anchor="middle" font-family="monospace" font-size="11" fill="#8A8A8A">#', idStr, '</text>'
        ));

        svg = string(abi.encodePacked(
            svg,
            '<text x="200" y="205" text-anchor="middle" font-family="Georgia,serif" font-size="', nameFontSize, '" fill="#0D0D0D">', name, '</text>',
            '<text x="200" y="', didY, '" text-anchor="middle" font-family="monospace" font-size="', didFontSize, '" fill="#8A8A8A">did:chitin:', name, '</text>',
            '<line x1="80" y1="340" x2="320" y2="340" stroke="#E8E0D0" stroke-width="1"/>',
            '<text x="200" y="365" text-anchor="middle" font-family="monospace" font-size="9" fill="#AEAAA0">chitin.id/', name, '</text>',
            '<text x="200" y="382" text-anchor="middle" font-family="monospace" font-size="9" letter-spacing="0.15em" fill="#AEAAA0">VERIFIED ON BASE L2</text>',
            '</svg>'
        ));

        return svg;
    }

    /// @notice Generate the JSON metadata
    function _generateJSON(string memory name, string memory idStr, string memory svg) private pure returns (string memory) {
        // Note: \u00b7 is Unicode for middle dot (·)
        string memory json = string(abi.encodePacked(
            '{"name":"', name,
            '","description":"Chitin Genesis Record #', idStr, ' \\u00b7 did:chitin:', name,
            '","external_url":"https://chitin.id/', name,
            '","image":"data:image/svg+xml;base64,', Base64.encode(bytes(svg)),
            '"}'
        ));

        return string(abi.encodePacked(
            "data:application/json;base64,",
            Base64.encode(bytes(json))
        ));
    }
}
