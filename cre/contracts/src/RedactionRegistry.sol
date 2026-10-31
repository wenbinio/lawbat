// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC165} from "./IERC165.sol";
import {IReceiver} from "./IReceiver.sol";

/// @title RedactionRegistry
/// @notice Stores a privacy-preserving redaction attestation. The payload is two
/// hashes, a risk level, and a timestamp. Document text is not accepted.
/// @dev In production `forwarder` is the Chainlink KeystoneForwarder. A local
/// dry-run sets it to the Anvil account that submits `onReport` directly.
contract RedactionRegistry is IReceiver {
    address public immutable forwarder;

    struct Attestation {
        bytes32 reportHash;
        uint8 riskLevel;
        uint64 ts;
        uint64 blockTime;
    }

    mapping(bytes32 => Attestation) private _attestations;

    error InvalidSender(address sender);
    error EmptyHash();
    error InvalidRiskLevel(uint8 level);

    event RedactionAttested(
        bytes32 indexed docHash,
        bytes32 reportHash,
        uint8 riskLevel,
        uint64 ts
    );

    constructor(address forwarder_) {
        if (forwarder_ == address(0)) revert InvalidSender(address(0));
        forwarder = forwarder_;
    }

    function onReport(bytes calldata metadata, bytes calldata report) external {
        // Workflow identity (id, name, owner) lives in `metadata`. This registry
        // does not store it. The forwarder already authenticated the report.
        metadata;
        if (msg.sender != forwarder) revert InvalidSender(msg.sender);
        (bytes32 docHash, bytes32 reportHash, uint8 riskLevel, uint64 ts) =
            abi.decode(report, (bytes32, bytes32, uint8, uint64));
        if (docHash == bytes32(0) || reportHash == bytes32(0)) revert EmptyHash();
        if (riskLevel > 3) revert InvalidRiskLevel(riskLevel);
        _attestations[docHash] = Attestation(reportHash, riskLevel, ts, uint64(block.timestamp));
        emit RedactionAttested(docHash, reportHash, riskLevel, ts);
    }

    function getAttestation(bytes32 docHash)
        external
        view
        returns (bytes32 reportHash, uint8 riskLevel, uint64 ts, uint64 blockTime)
    {
        Attestation memory item = _attestations[docHash];
        return (item.reportHash, item.riskLevel, item.ts, item.blockTime);
    }

    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return interfaceId == type(IReceiver).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}
