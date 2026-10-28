// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract LogVault {

    struct WindowRecord {
        bytes32 windowHash;
        bytes32 previousHash;
        uint256 timestamp;
        uint256 numLines;
        bool exists;
    }

    mapping(uint256 => WindowRecord) public windows;
    uint256 public totalWindows;

    event WindowAnchored(uint256 indexed windowId, bytes32 windowHash, uint256 timestamp);

    function anchorWindow(
        uint256 windowId,
        bytes32 windowHash,
        bytes32 previousHash,
        uint256 numLines
    ) public {
        require(!windows[windowId].exists, "Window already anchored");

        windows[windowId] = WindowRecord({
            windowHash: windowHash,
            previousHash: previousHash,
            timestamp: block.timestamp,
            numLines: numLines,
            exists: true
        });

        totalWindows += 1;

        emit WindowAnchored(windowId, windowHash, block.timestamp);
    }

    function getWindow(uint256 windowId) public view returns (
        bytes32 windowHash,
        bytes32 previousHash,
        uint256 timestamp,
        uint256 numLines,
        bool exists
    ) {
        WindowRecord memory record = windows[windowId];
        return (record.windowHash, record.previousHash, record.timestamp, record.numLines, record.exists);
    }
}