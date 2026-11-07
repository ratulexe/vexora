// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Vexora threat report registry
/// @notice Records cryptographic commitments (hashes) to threat reports, with their
/// revision history, disputes and validation status.
/// @dev Report contents, raw URLs and personal data stay off-chain. A record proves a
/// report has not changed since it was registered, and who registered it and when.
/// It does not prove the report is true.
contract ThreatReportRegistry {
    enum Status {
        None,
        Active,
        Superseded,
        Disputed,
        Validated,
        Rejected
    }

    struct Report {
        address reporter;
        uint64 registeredAt;
        Status status;
        uint8 classification; // 0 Low Risk, 1 Suspicious, 2 High Risk, 3 Confirmed Malicious, 4 Inconclusive
        uint8 kind; // 0 link, 1 message
        bytes32 indicatorHash; // keccak256 of the main domain, or zero
        bytes32 previous; // Commitment this report revises, or zero
        bytes32 next; // Commitment that revised this report, or zero
        uint32 disputes;
    }

    address public owner;
    mapping(address => bool) public validators;
    mapping(bytes32 => Report) private reports;
    mapping(bytes32 => uint256) public indicatorReportCount;
    uint256 public reportCount;

    event ReportRegistered(
        bytes32 indexed commitment,
        bytes32 indexed indicatorHash,
        address indexed reporter,
        uint8 classification,
        uint8 kind,
        uint64 registeredAt
    );
    event ReportRevised(bytes32 indexed previous, bytes32 indexed commitment, address indexed reporter);
    event ReportDisputed(bytes32 indexed commitment, address indexed disputer, bytes32 reasonHash);
    event ReportValidated(bytes32 indexed commitment, address indexed validator, bool accepted);
    event ValidatorChanged(address indexed validator, bool allowed);

    error NotOwner();
    error NotValidator();
    error NotReporter();
    error EmptyCommitment();
    error InvalidClassification();
    error AlreadyRegistered(bytes32 commitment);
    error UnknownReport(bytes32 commitment);
    error AlreadyRevised(bytes32 commitment);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        validators[msg.sender] = true;
        emit ValidatorChanged(msg.sender, true);
    }

    function registerReport(bytes32 commitment, bytes32 indicatorHash, uint8 classification, uint8 kind)
        external
    {
        _register(commitment, indicatorHash, classification, kind, bytes32(0));
    }

    /// @notice Publish a corrected version of your own report. The old one is kept and marked Superseded.
    function reviseReport(
        bytes32 previous,
        bytes32 commitment,
        bytes32 indicatorHash,
        uint8 classification,
        uint8 kind
    ) external {
        Report storage old = _existing(previous);
        if (old.reporter != msg.sender) revert NotReporter();
        if (old.next != bytes32(0)) revert AlreadyRevised(previous);
        _register(commitment, indicatorHash, classification, kind, previous);
        old.next = commitment;
        old.status = Status.Superseded;
        emit ReportRevised(previous, commitment, msg.sender);
    }

    /// @notice Anyone can dispute a report. The reason is kept off-chain; only its hash is recorded.
    function disputeReport(bytes32 commitment, bytes32 reasonHash) external {
        Report storage report = _existing(commitment);
        report.disputes += 1;
        if (report.status == Status.Active) report.status = Status.Disputed;
        emit ReportDisputed(commitment, msg.sender, reasonHash);
    }

    /// @notice A validator confirms or rejects a report after reviewing its evidence.
    function validateReport(bytes32 commitment, bool accepted) external {
        if (!validators[msg.sender]) revert NotValidator();
        Report storage report = _existing(commitment);
        report.status = accepted ? Status.Validated : Status.Rejected;
        emit ReportValidated(commitment, msg.sender, accepted);
    }

    function setValidator(address validator, bool allowed) external onlyOwner {
        validators[validator] = allowed;
        emit ValidatorChanged(validator, allowed);
    }

    /// @notice Hash the off-chain report package and pass the result here to check it.
    function verifyReport(bytes32 commitment) external view returns (bool registered, Report memory report) {
        report = reports[commitment];
        registered = report.status != Status.None;
    }

    function _register(
        bytes32 commitment,
        bytes32 indicatorHash,
        uint8 classification,
        uint8 kind,
        bytes32 previous
    ) private {
        if (commitment == bytes32(0)) revert EmptyCommitment();
        if (classification > 4 || kind > 1) revert InvalidClassification();
        if (reports[commitment].status != Status.None) revert AlreadyRegistered(commitment);

        uint64 registeredAt = uint64(block.timestamp);
        reports[commitment] = Report({
            reporter: msg.sender,
            registeredAt: registeredAt,
            status: Status.Active,
            classification: classification,
            kind: kind,
            indicatorHash: indicatorHash,
            previous: previous,
            next: bytes32(0),
            disputes: 0
        });
        reportCount += 1;
        if (indicatorHash != bytes32(0)) indicatorReportCount[indicatorHash] += 1;
        emit ReportRegistered(commitment, indicatorHash, msg.sender, classification, kind, registeredAt);
    }

    function _existing(bytes32 commitment) private view returns (Report storage report) {
        report = reports[commitment];
        if (report.status == Status.None) revert UnknownReport(commitment);
    }
}
