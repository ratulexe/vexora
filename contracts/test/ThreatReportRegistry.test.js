const { expect } = require("chai");
const { ethers } = require("hardhat");

const Status = { None: 0n, Active: 1n, Superseded: 2n, Disputed: 3n, Validated: 4n, Rejected: 5n };
const hashReport = (report) => ethers.id(JSON.stringify(report));
const DOMAIN = ethers.id("sbi-kyc-update.in");

describe("ThreatReportRegistry", () => {
  const report = { domain: "sbi-kyc-update.in", classification: "High Risk", salt: "a1" };
  let registry;
  let owner;
  let reporter;
  let other;

  beforeEach(async () => {
    [owner, reporter, other] = await ethers.getSigners();
    registry = await (await ethers.getContractFactory("ThreatReportRegistry")).deploy();
  });

  const register = (signer = reporter, data = report, classification = 2) =>
    registry.connect(signer).registerReport(hashReport(data), DOMAIN, classification, 0);

  describe("registration and verification", () => {
    it("records who registered a report and when", async () => {
      await expect(register()).to.emit(registry, "ReportRegistered");
      const [registered, record] = await registry.verifyReport(hashReport(report));
      expect(registered).to.equal(true);
      expect(record.reporter).to.equal(reporter.address);
      expect(record.status).to.equal(Status.Active);
      expect(record.classification).to.equal(2n);
      expect(await registry.reportCount()).to.equal(1n);
      expect(await registry.indicatorReportCount(DOMAIN)).to.equal(1n);
    });

    it("fails verification when any part of the report changes", async () => {
      await register();
      const [registered] = await registry.verifyReport(hashReport({ ...report, classification: "Low Risk" }));
      expect(registered).to.equal(false);
    });

    it("rejects duplicate, empty and invalid reports", async () => {
      await register();
      await expect(register()).to.be.revertedWithCustomError(registry, "AlreadyRegistered");
      await expect(registry.registerReport(ethers.ZeroHash, DOMAIN, 1, 0)).to.be.revertedWithCustomError(
        registry,
        "EmptyCommitment",
      );
      await expect(register(reporter, { ...report, salt: "b2" }, 9)).to.be.revertedWithCustomError(
        registry,
        "InvalidClassification",
      );
    });

    it("counts repeat reports of the same domain", async () => {
      await register();
      await register(other, { ...report, salt: "b2" });
      expect(await registry.indicatorReportCount(DOMAIN)).to.equal(2n);
    });
  });

  describe("revisions", () => {
    it("links a revision to the original and marks the original superseded", async () => {
      await register();
      const revised = { ...report, classification: "Confirmed Malicious" };
      await expect(
        registry.connect(reporter).reviseReport(hashReport(report), hashReport(revised), DOMAIN, 3, 0),
      ).to.emit(registry, "ReportRevised");

      const [, original] = await registry.verifyReport(hashReport(report));
      const [, latest] = await registry.verifyReport(hashReport(revised));
      expect(original.status).to.equal(Status.Superseded);
      expect(original.next).to.equal(hashReport(revised));
      expect(latest.previous).to.equal(hashReport(report));
    });

    it("only lets the original reporter revise, and only once", async () => {
      await register();
      const revised = hashReport({ ...report, salt: "c3" });
      await expect(
        registry.connect(other).reviseReport(hashReport(report), revised, DOMAIN, 3, 0),
      ).to.be.revertedWithCustomError(registry, "NotReporter");
      await registry.connect(reporter).reviseReport(hashReport(report), revised, DOMAIN, 3, 0);
      await expect(
        registry.connect(reporter).reviseReport(hashReport(report), hashReport({ salt: "d4" }), DOMAIN, 3, 0),
      ).to.be.revertedWithCustomError(registry, "AlreadyRevised");
    });
  });

  describe("disputes and validation", () => {
    it("lets anyone dispute a report", async () => {
      await register();
      await expect(registry.connect(other).disputeReport(hashReport(report), ethers.id("false positive")))
        .to.emit(registry, "ReportDisputed");
      const [, record] = await registry.verifyReport(hashReport(report));
      expect(record.status).to.equal(Status.Disputed);
      expect(record.disputes).to.equal(1n);
    });

    it("lets only validators confirm or reject", async () => {
      await register();
      await expect(registry.connect(other).validateReport(hashReport(report), true)).to.be.revertedWithCustomError(
        registry,
        "NotValidator",
      );
      await registry.connect(owner).setValidator(other.address, true);
      await registry.connect(other).validateReport(hashReport(report), false);
      const [, record] = await registry.verifyReport(hashReport(report));
      expect(record.status).to.equal(Status.Rejected);
    });

    it("lets only the owner manage validators", async () => {
      await expect(registry.connect(other).setValidator(other.address, true)).to.be.revertedWithCustomError(
        registry,
        "NotOwner",
      );
    });

    it("refuses to act on unknown reports", async () => {
      await expect(registry.disputeReport(ethers.id("missing"), ethers.ZeroHash)).to.be.revertedWithCustomError(
        registry,
        "UnknownReport",
      );
    });
  });
});
