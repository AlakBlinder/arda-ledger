// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/// @title Ledger
/// @notice Manages state history for DIDs with cryptographic verification
/// @dev Uses AccessControl for managing write permissions
contract Ledger is AccessControl, Pausable {
    bytes32 public constant UPDATER_ROLE = keccak256("UPDATER_ROLE");
    uint256 public constant MAX_STRING_LENGTH = 1000; // Arbitrary limit, adjust as needed

    enum EventType {
        PROPERTY_CREATED,
        PROPERTY_LINKED_TO_SPV,
    }

    struct DIDState {
        string did;             // DID of the asset
        uint256 timestamp;      // Block timestamp of update
        EventType eventType;    // Type of event
        string storjUrl;        // Link to JSON file stored on Storj
        bytes32 dataHash;       // Hash of JSON stored in Storj (SHA-256)
        bytes32 previousHash;   // Hash of previous state (for history tracking)
    }

    // Mapping of DID to chronological list of state changes
    mapping(string => DIDState[]) private didStates;

    event DIDStateUpdated(
        string indexed did,
        uint256 timestamp,
        EventType indexed eventType,
        string storjUrl,
        bytes32 indexed dataHash,
        bytes32 previousHash
    );

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(UPDATER_ROLE, msg.sender);
    }

    /// @notice Adds a new state update for a DID
    /// @param _did The DID identifier
    /// @param _eventType The type of event occurring
    /// @param _storjUrl URL pointing to the JSON data in Storj
    /// @param _dataHash SHA-256 hash of the JSON data
    function addDIDState(
        string memory _did, 
        EventType _eventType, 
        string memory _storjUrl,
        bytes32 _dataHash
    ) public onlyRole(UPDATER_ROLE) whenNotPaused {
        // Add DID format validation
        require(validateDIDFormat(_did), "Invalid DID format");
        require(bytes(_did).length > 0 && bytes(_did).length <= MAX_STRING_LENGTH, "Invalid DID length");
        require(bytes(_storjUrl).length > 0 && bytes(_storjUrl).length <= MAX_STRING_LENGTH, "Invalid URL length");
        require(_dataHash != bytes32(0), "Invalid data hash");

        // Get the latest state of the DID
        bytes32 previousStateHash = bytes32(0);
        uint256 length = didStates[_did].length;
        if (length > 0) {
            previousStateHash = didStates[_did][length - 1].dataHash;
        }

        // Create a new state entry
        DIDState memory newState = DIDState({
            did: _did,
            timestamp: block.timestamp,
            eventType: _eventType,
            storjUrl: _storjUrl,
            dataHash: _dataHash,
            previousHash: previousStateHash
        });

        // Store the new state in the array
        didStates[_did].push(newState);

        // Emit an event for tracking
        emit DIDStateUpdated(_did, block.timestamp, _eventType, _storjUrl, _dataHash, previousStateHash);
    }

    /// @notice Fetches the full history of a DID
    function getDIDHistory(string memory _did) public view returns (DIDState[] memory) {
        return didStates[_did];
    }

    /// @notice Fetches the latest state of a DID
    function getLatestDIDState(string memory _did) public view returns (DIDState memory) {
        require(didStates[_did].length > 0, "No state found for this DID");
        return didStates[_did][didStates[_did].length - 1];
    }

    /// @notice Validates the format of a DID string
    /// @dev Basic validation - can be enhanced based on your DID format
    function validateDIDFormat(string memory _did) internal pure returns (bool) {
        bytes memory didBytes = bytes(_did);
        return didBytes.length >= 7 && // min length for "did:xxx"
               didBytes[0] == "d" &&
               didBytes[1] == "i" &&
               didBytes[2] == "d" &&
               didBytes[3] == ":";
    }

    /// @notice Verifies the integrity of a DID's history
    /// @param _did The DID to verify
    /// @return bool True if the history is valid
    function verifyDIDHistory(string memory _did) public view returns (bool) {
        DIDState[] memory history = didStates[_did];
        if (history.length == 0) return true;
        
        for (uint i = 1; i < history.length; i++) {
            if (history[i].previousHash != history[i-1].dataHash) {
                return false;
            }
        }
        return true;
    }

    /// @notice Pauses the contract
    function pause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract
    function unpause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Gets the maximum allowed string length
    function getMaxStringLength() public view returns (uint256) {
        return MAX_STRING_LENGTH;
    }

    /// @notice Sets a new maximum string length
    /// @param _newLength The new maximum length to set
    function setMaxStringLength(uint256 _newLength) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_newLength > 0, "Length must be greater than 0");
        MAX_STRING_LENGTH = _newLength;
    }

    /// @notice Checks if a DID exists
    /// @param _did The DID to check
    function didExists(string memory _did) public view returns (bool) {
        return didStates[_did].length > 0;
    }

    /// @notice Gets the number of states for a DID
    /// @param _did The DID to check
    function getDIDStateCount(string memory _did) public view returns (uint256) {
        return didStates[_did].length;
    }
}