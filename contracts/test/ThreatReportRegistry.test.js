const { expect } = require("chai");
const { ethers } = require("hardhat");

const hashReport = (report) => ethers.id(JSON.stringify(report));

describe("ThreatReportRegistry", () => {
  const report = { domain: "paypa1-login.example", classification: "Suspicious" };
  let registry;
  let reporter;

  beforeEach(async () => {
    [reporter] = await ethers.getSigners();
    const factory = await ethers.getContractFactory("ThreatReportRegistry");
    registry = await factory.deploy();
  });

  it("verifies a registered report", async () => {
    await registry.registerReport(hashReport(report));

    const result = await registry.verifyReport(hashReport(report));
    expect(result.registered).to.equal(true);
    expect(result.reporter).to.equal(reporter.address);
  });

  it("fails verification when the report is changed", async () => {
    await registry.registerReport(hashReport(report));

    const tampered = { ...report, classification: "Low Risk" };
    const result = await registry.verifyReport(hashReport(tampered));
    expect(result.registered).to.equal(false);
  });

  it("rejects duplicate commitments", async () => {
    await registry.registerReport(hashReport(report));

    await expect(registry.registerReport(hashReport(report))).to.be.revertedWithCustomError(
      registry,
      "AlreadyRegistered",
    );
  });

  it("rejects an empty commitment", async () => {
    await expect(registry.registerReport(ethers.ZeroHash)).to.be.revertedWithCustomError(
      registry,
      "EmptyCommitment",
    );
  });
});
