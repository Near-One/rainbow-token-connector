const SCHEMA = {
    'SetMetadataResult': {
      kind: 'struct', fields: [
        ['token', 'string'],
        ['name', 'string'],
        ['symbol', 'string'],
        ['decimals', 'u8'],
        ['blockHeight', 'u64'],
      ]
    },
    'LockResult': {
      kind: 'struct', fields: [
        ['token', 'string'],
        ['amount', 'u128'],
        ['recipient', [20]],
      ]
    }
  };

const ADMIN_ROLE = '0x0000000000000000000000000000000000000000000000000000000000000000';


const createEmptyToken = async (nearTokenId, BridgeTokenFactory, BridgeTokenInstance) => {
  await BridgeTokenFactory.newBridgeToken(nearTokenId)
  const tokenProxyAddress = await BridgeTokenFactory.nearToEthToken(nearTokenId)
  const token = BridgeTokenInstance.attach(tokenProxyAddress)
  return {tokenProxyAddress, token}
}

const createDefaultERC20Metadata = (nearTokenId, blockHeight) => {
   return {
    token: nearTokenId,
    name: 'NEAR ERC20',
    symbol: 'NEAR',
    decimals: 18,
    blockHeight
}}

module.exports = { SCHEMA, createEmptyToken, createDefaultERC20Metadata, ADMIN_ROLE };