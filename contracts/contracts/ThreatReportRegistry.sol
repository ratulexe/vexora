// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Records commitments (hashes) to threat reports. The reports themselves,
/// including raw URLs and personal data, stay off-chain.
/// @dev A record proves a report's integrity and history, not that the report is true.
contract ThreatReportRegistry {
    struct Record {
        address reporter;
        uint64 registeredAt;
    }

    mapping(bytes32 => Record) private records;

    event ReportRegistered(bytes32 indexed commitment, address indexed reporter, uint64 registeredAt);

    error AlreadyRegistered(bytes32 commitment);
    error EmptyCommitment();

    function registerReport(bytes32 commitment) external {
        if (commitment == bytes32(0)) revert EmptyCommitment();
        if (records[commitment].registeredAt != 0) revert AlreadyRegistered(commitment);

        uint64 registeredAt = uint64(block.timestamp);
        records[commitment] = Record(msg.sender, registeredAt);
        emit ReportRegistered(commitment, msg.sender, registeredAt);
    }

    /// @notice Hash the off-chain report and pass the result here to check its integrity.
    function verifyReport(bytes32 commitment)
        external
        view
        returns (bool registered, address reporter, uint64 registeredAt)
    {
        Record memory record = records[commitment];
        return (record.registeredAt != 0, record.reporter, record.registeredAt);
    }
}
