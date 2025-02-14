// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ArdaInsights is AccessControl {
    
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;

    uint256 public constant MAX_STRING_LENGTH = 1000;

    // Track valid document types
    mapping(string => bool) private validDocumentTypes;
    string[] private documentTypeList;

    struct DocumentVerification {
        bytes32 dataHash;       // Hash of the document
        bytes oracleSignature;  // Oracle's digital signature
        uint256 timestamp;      // Timestamp of verification
    }

    // Mapping from Property DID to Document Type to Document Verification Data
    mapping(string => mapping(string => DocumentVerification)) private propertyDocuments;

    // Event emitted when a new document is verified and stored
    event DocumentVerified(
        string indexed propertyDID,
        string documentType,
        bytes32 dataHash,
        bytes oracleSignature,
        uint256 timestamp
    );

    event DocumentVerificationRevoked(
        string indexed propertyDID,
        string documentType
    );

    event DocumentTypeAdded(string documentType);
    event DocumentTypeRemoved(string documentType);

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(ORACLE_ROLE, msg.sender);
    }

    modifier validDocumentType(string memory _documentType) {
        require(validDocumentTypes[_documentType], "Invalid document type");
        _;
    }

    /// @notice Add a new valid document type
    /// @param _documentType The new document type to add
    function addDocumentType(string memory _documentType) 
        public 
        onlyRole(ADMIN_ROLE) 
    {
        require(bytes(_documentType).length > 0 && bytes(_documentType).length <= MAX_STRING_LENGTH, "Invalid type length");
        require(!validDocumentTypes[_documentType], "Document type already exists");
        
        validDocumentTypes[_documentType] = true;
        documentTypeList.push(_documentType);
        
        emit DocumentTypeAdded(_documentType);
    }

    /// @notice Remove a document type
    /// @param _documentType The document type to remove
    function removeDocumentType(string memory _documentType) 
        public 
        onlyRole(ADMIN_ROLE) 
    {
        require(validDocumentTypes[_documentType], "Document type doesn't exist");
        
        validDocumentTypes[_documentType] = false;
        
        // Remove from list
        for (uint i = 0; i < documentTypeList.length; i++) {
            if (keccak256(bytes(documentTypeList[i])) == keccak256(bytes(_documentType))) {
                documentTypeList[i] = documentTypeList[documentTypeList.length - 1];
                documentTypeList.pop();
                break;
            }
        }
        
        emit DocumentTypeRemoved(_documentType);
    }

    /// @notice Get all valid document types
    function getDocumentTypes() public view returns (string[] memory) {
        return documentTypeList;
    }

    /// @notice Check if a document type is valid
    function isValidDocumentType(string memory _documentType) public view returns (bool) {
        return validDocumentTypes[_documentType];
    }

    /// @notice Store a verified document for a property
    /// @param _propertyDID Unique Decentralized Identifier for the property
    /// @param _documentType Type of document (e.g., "Title Deed", "Tax Receipt")
    /// @param _dataHash SHA-256 hash of the document
    /// @param _oracleSignature Digital signature from the Oracle
    function storeDocumentVerification(
        string memory _propertyDID,
        string memory _documentType,
        bytes32 _dataHash,
        bytes memory _oracleSignature
    ) public onlyRole(ORACLE_ROLE) validDocumentType(_documentType) {
        require(bytes(_propertyDID).length > 0 && bytes(_propertyDID).length <= MAX_STRING_LENGTH, "Invalid DID length");
        require(bytes(_documentType).length > 0 && bytes(_documentType).length <= MAX_STRING_LENGTH, "Invalid document type length");
        require(_dataHash != bytes32(0), "Invalid data hash");
        require(_oracleSignature.length > 0, "Invalid signature");
        
        propertyDocuments[_propertyDID][_documentType] = DocumentVerification({
            dataHash: _dataHash,
            oracleSignature: _oracleSignature,
            timestamp: block.timestamp
        });

        emit DocumentVerified(_propertyDID, _documentType, _dataHash, _oracleSignature, block.timestamp);
    }

    /// @notice Fetch the latest verification details for a specific document of a property
    /// @param _propertyDID Unique Decentralized Identifier for the property
    /// @param _documentType Type of document (e.g., "Title Deed", "Tax Receipt")
    /// @return dataHash, oracleSignature, timestamp
    function getDocumentVerification(string memory _propertyDID, string memory _documentType) 
        public 
        view 
        validDocumentType(_documentType)
        returns (bytes32, bytes memory, uint256) 
    {
        require(propertyDocuments[_propertyDID][_documentType].timestamp != 0, "No verification found for this document");
        DocumentVerification memory record = propertyDocuments[_propertyDID][_documentType];
        return (record.dataHash, record.oracleSignature, record.timestamp);
    }

    function revokeDocumentVerification(
        string memory _propertyDID,
        string memory _documentType
    ) public onlyRole(ORACLE_ROLE) validDocumentType(_documentType) {
        require(propertyDocuments[_propertyDID][_documentType].timestamp != 0, "No verification exists");
        delete propertyDocuments[_propertyDID][_documentType];
        emit DocumentVerificationRevoked(_propertyDID, _documentType);
    }
}
