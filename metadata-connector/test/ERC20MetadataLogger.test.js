const { expect } = require('chai');

describe("ERC20MetadataLogger", function () {
  it("Should log erc20 metadata", async function () {
    const SampleERC20 = await ethers.getContractFactory('SampleERC20')
    const sampleERC20 = await SampleERC20.deploy()
    const ERC20MetadataLogger = await ethers.getContractFactory("ERC20MetadataLogger");
    const erc20MetadataLogger = await ERC20MetadataLogger.deploy();
    await erc20MetadataLogger.deployed();

    const tx = await erc20MetadataLogger.log(sampleERC20.address)
    const { events } = await tx.wait()
    const args = events.find(({ event }) => event === 'Log').args
    expect(args.erc20).to.equal(sampleERC20.address)
    expect(args.name).to.equal("SampleERC20")
    expect(args.symbol).to.equal("ERC")
    expect(args.decimals).to.equal(18)
  });
  it("Should revert if in case of non-erc20 compliant", async function () {
    //TBD
  })
});
