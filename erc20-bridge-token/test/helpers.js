const { serialize } = require('rainbow-bridge-lib/borsh.js');
const { borshifyOutcomeProof } = require('rainbow-bridge-lib/borshify-proof.js');

const SCHEMA = {
  'SetMetadataResult': {
    kind: 'struct', fields: [
      ['prefix', [32]],
      ['token', 'string'],
      ['name', 'string'],
      ['symbol', 'string'],
      ['decimals', 'u8'],
      ['blockHeight', 'u64'],
    ]
  },
  'LockResult': {
    kind: 'struct', fields: [
      ['prefix', [32]],
      ['token', 'string'],
      ['amount', 'u128'],
      ['recipient', [20]],
    ]
  }
};

const ADMIN_ROLE = '0x0000000000000000000000000000000000000000000000000000000000000000';
const RESULT_PREFIX_LOCK = Buffer.from("0a9eb877458579dbce83ea57d556be50d1c3160bb5f1719fb172bd3300ac8623", "hex");
const RESULT_PREFIX_METADATA = Buffer.from("b315d4d6e8f235f5fabb0b1a0f118507f6c8542fae8e1a9566abe60762047c16", "hex");

const createEmptyToken = async (nearTokenId, BridgeTokenFactory, BridgeTokenInstance) => {
  const { metadataProof, proofBlockHeight } = getMetadataProof(nearTokenId)
  await BridgeTokenFactory.newBridgeToken(nearTokenId, borshifyOutcomeProof(metadataProof), proofBlockHeight)
  const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId)
  const token = BridgeTokenInstance.attach(tokenProxyAddress)
  return { tokenProxyAddress, token }
}

function getMetadataProof(nearTokenId) {
  const { proof, proofBlockHeight } = getProofTemplate();
  const metadata = createDefaultERC20Metadata(nearTokenId, proofBlockHeight);
  proof.outcome_proof.outcome.receipt_ids[0] = generateRandomBase58(64);
  proof.outcome_proof.outcome.status.SuccessValue = serialize(
    SCHEMA,
    "SetMetadataResult",
    metadata
  ).toString("base64");

  return { metadataProof: proof, proofBlockHeight };
}

function getProofTemplate() {
  return {
    proof: require("./proof_template.json"),
    proofBlockHeight: 1089,
  };
}

const createDefaultERC20Metadata = (nearTokenId, blockHeight) => {
  return {
    prefix: RESULT_PREFIX_METADATA,
    token: nearTokenId,
    name: 'NEAR ERC20',
    symbol: 'NEAR',
    decimals: 18,
    blockHeight
  }
}

const generateRandomBase58 = (rawSize) => {
  var rawInput = "0x";
  var alphabet = "123456789abcdef";

  for (var i = 0; i < rawSize; i++) {
    rawInput += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  }

  return ethers.utils.base58.encode(rawInput);
}

module.exports = { SCHEMA, createEmptyToken, createDefaultERC20Metadata, generateRandomBase58, ADMIN_ROLE, RESULT_PREFIX_LOCK, RESULT_PREFIX_METADATA };