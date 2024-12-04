function metadataSignature(tokenId) {
  const signatures = [
    {
      payload: {
        token: "wrap.testnet",
        name: "Wrapped NEAR fungible token",
        symbol: "wNEAR",
        decimals: 24
      },
      signature: "0x43D447B8FF105D740FA7B68D506163D33D8AB2831250DB66A074E45FCF218E0C2EC50105AB9AEDD43556D75C22E790CAEF7F6DC486953D5B266859E23D36C3AB1C"
    },
    {
      payload: {
        token: "token-bridge-test.testnet",
        name: "Bridge Token",
        symbol: "TBT",
        decimals: 8
      },
      signature: "0x1D665C94803E5508D7EB34C43F54CB7503B6C14573B8A39F46EFEAF10CF2F68724F18F44F53C8AE3729470B7DDC256D0169F7BBF82CE39F48A95351DAA076C861C"
    }
  ];

  const data = signatures.find(s => s.payload.token === tokenId);
  if (data === undefined) throw new Error(`Metadata not found for token ${tokenId}`);

  return data;
}

function depositSignature(tokenId, recipient) {
  const signatures = [
    {
      payload: {
        nonce: 2,
        token: "wrap.testnet",
        amount: 1,
        recipient: "0x3A445243376C32fAba679F63586e236F77EA601e",
        relayer: "0x0000000000000000000000000000000000000000",
      },
      signature: "0x4B7305FD501E44EEF53E876DE0F8F4F848C00179FD27B0E4942EC2C94816C5CA33C583D7D386B77BF7AD121ED4FE0DB5AF8C730CC7B2D505987616B532F492AF1B"
    },
    {
      payload: {
        nonce: 10,
        token: "token-bridge-test.testnet",
        amount: 200,
        recipient: "0x5a08feed678c056650b3eb4a5cb1b9bb6f0fe265",
        relayer: "0x0000000000000000000000000000000000000000",
      },
      signature: "0xE5C500D3D21289C620BF7CA0E9049B24B7D4D9864C5E3F09477BCCB7E6524E5810DDCDFE5988F08C36B6AC70D81E443D91CBA0E43935ECEDB8F14BD4222464FA1C"
    },
    {
      payload: {
        nonce: 11,
        token: "wrap.testnet",
        amount: 25,
        recipient: "0x5a08feed678c056650b3eb4a5cb1b9bb6f0fe265",
        relayer: "0x0000000000000000000000000000000000000000",
      },
      signature: "0x316AFD2FFC056DD266296B023E2509222FC6ED9FAE44583414BE6E478BF62C5238E413341093B0E8C1A6192EFF1C0C4FFFB0D405C48993555E99B11A987891C61C"
    },
    {
      payload: {
        nonce: 12,
        token: "token-bridge-test.testnet",
        amount: 10,
        recipient: "0x3a445243376c32faba679f63586e236f77ea601e",
        relayer: "0x0000000000000000000000000000000000000000",
      },
      signature: "0x15E146799FF4D5FC190A72633A0FAC14C399D2D9CFCEA1DAC8C1D0913C6698832C2AEF2C5CA6AA731089EA31559A57AE2586744DDDE7A196A3BDA26A38B8387A1C"
    }
  ];

  const data = signatures.find(s => s.payload.token === tokenId && s.payload.recipient.toLowerCase() === recipient.toLowerCase());
  if (data === undefined) throw new Error(`Deposit not found for token ${tokenId} and recipient ${recipient}`);

  return data;
}

module.exports = { metadataSignature, depositSignature };