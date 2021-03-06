/**
 * Lib for CoinID
 */

import bip39 from "react-native-bip39";

import {
  getAddressTypeInfo,
  getAddInputFunctionFromDerivation,
  getAddressFunctionFromDerivation,
  getSignInputFunctionFromDerivation
} from "coinid-address-types";

const bitcoin = require("bitcoinjs-lib");
const bitcoinMessage = require("bitcoinjs-message");
const md5 = require("md5");
const bip38 = require("bip38-async");
const wif = require("wif");

const supportedNetworks = {
  xmy: bitcoin.networks.myriad,
  ltc: bitcoin.networks.litecoin,
  btc: bitcoin.networks.bitcoin,
  tbtc: bitcoin.networks.testnet,
  grs: bitcoin.networks.groestlcoin,
  tgrs: bitcoin.networks["groestlcoin-testnet"]
};

/**
 * Generates Mnemonic based on bip39
 */
const generateMnemonic = function() {
  try {
    return bip39.generateMnemonic(128); // default to 128
  } catch (e) {
    return false;
  }
};

/**
 * Retrieves network parameters from ticker string
 */
const getNetworkFromTicker = function(ticker) {
  return supportedNetworks[ticker.toLowerCase()];
};

/**
 * Gets Address from script
 */
const scriptToAddress = function(script, network) {
  return bitcoin.address.fromOutputScript(script, network);
};

const getBasePublicKey = function(network, mnemonic) {
  const hdNode = getBaseHDNode(network, mnemonic);
  return hdNode.neutered().toBase58();
};

const getHdNodeFromPublicKey = function(network, pubKey) {
  const hdNode = bitcoin.HDNode.fromBase58(pubKey, network);
  return hdNode;
};

const verifyOwner = function(ownerCheck, network, mnemonic) {
  if (ownerCheck) {
    const { derivationPath, address } = parseOwnerCheck(ownerCheck);

    const derivedNode = createHDNodeFromDerivationPath(
      derivationPath,
      network,
      mnemonic
    );

    const derivedAddress = getAddressFunctionFromDerivation(derivationPath)(
      derivedNode
    );
    const shortenedAddress = derivedAddress.substr(0, address.length);

    if (shortenedAddress.toUpperCase() !== address.toUpperCase()) {
      throw "Wallet not created from this COINiD";
    }
  }

  return true;
};

var verifyChangeOutputs = function(changeOutputs, changeDerivationPathArr, network, mnemonic) {
  // allows older wallets to skip check... temporary until people have upgraded enough to the latest version...
  if(!changeDerivationPathArr) {
    return true;
  }

  if(changeOutputs.length !== changeDerivationPathArr.length) {
    throw('Could not verify derivation path');
  }

  if(changeOutputs.length === 0) {
    // nothing to verify
    return true;
  }

  var hdNode = getBaseHDNode(network, mnemonic);

  // fetch derivationpath from changeoutput index because
  const ownedAddresses = changeOutputs.map((_, i) => {
    var derivationPath = changeDerivationPathArr[i];
    var derivedNode = hdNode.derivePath(derivationPath);
    var derivedAddress = getAddressFunctionFromDerivation(derivationPath)(derivedNode);
    return derivedAddress;
  });

  const changeAddresses = changeOutputs.map(({address}) => address);
  const notOwnedAddresses = changeAddresses.filter(address => ownedAddresses.indexOf(address) === -1);

  if(notOwnedAddresses.length > 0) {
    throw('Change address not created from this COINiD Vault!');
  }

  return true;
}

var parseOwnerCheck = function(ownerCheck) {
  const splitData = ownerCheck.split("+");
  const derivationPath = reverseQrFriendlyDerivationPath(splitData[0]);
  const address = splitData[1];

  return {
    derivationPath,
    address
  };
};

const cachedHDNodeMap = {};

const getCachedHDNodeKey = (derivationPath, network, mnemonic) =>
  md5(derivationPath + network.ticker + mnemonic);

const getCachedHDNode = (derivationPath, network, mnemonic) => {
  const cacheKey = getCachedHDNodeKey(derivationPath, network, mnemonic);
  return cachedHDNodeMap[cacheKey];
};

const setCachedHDNode = (hdNode, derivationPath, network, mnemonic) => {
  const cacheKey = getCachedHDNodeKey(derivationPath, network, mnemonic);
  cachedHDNodeMap[cacheKey] = hdNode;
};

/**
 * Creates HDNode from mnemonic
 */
var getBaseHDNode = function(network, mnemonic) {
  let hdNode = getCachedHDNode("m", network, mnemonic);

  if (hdNode === undefined) {
    hdNode = bitcoin.HDNode.fromSeedBuffer(
      bip39.mnemonicToSeed(mnemonic),
      network
    );
    setCachedHDNode(hdNode, "m", network, mnemonic);
  }

  return hdNode;
};

/**
 * Gets keyPair from derivation path and Mnemonic
 */
const createHDNodeFromDerivationPath = function(
  derivationPath,
  network,
  mnemonic
) {
  var cachedHDNode = getCachedHDNode(derivationPath, network, mnemonic);
  if (cachedHDNode !== undefined) {
    return cachedHDNode;
  }

  let currentHDNode = getBaseHDNode(network, mnemonic);

  let splitPath = derivationPath.split("/");
  if (splitPath[0] === "m") {
    splitPath = splitPath.slice(1);
  }

  for (let i = 0; i < splitPath.length; i++) {
    const path = splitPath[i];
    const fullPath = `m/${splitPath.slice(0, i + 1).join("/")}`;

    var cachedHDNode = getCachedHDNode(fullPath, network, mnemonic);
    if (cachedHDNode === undefined) {
      currentHDNode = currentHDNode.derivePath(path);
      setCachedHDNode(currentHDNode, fullPath, network, mnemonic);
    } else {
      currentHDNode = cachedHDNode;
    }
  }
  return currentHDNode;
};

/**
 * Creates Public Keys for purposeArr which can derive chain and index. This is transfered to the wallet to set up an account..
 */
const createPublicKeysFromDerivationPaths = function(
  derivationPathArr,
  network,
  mnemonic
) {
  return derivationPathArr.map(derivationPath => {
    const hdNode = createHDNodeFromDerivationPath(
      derivationPath,
      network,
      mnemonic
    );

    return {
      derivationPath,
      publicKey: hdNode.neutered().toBase58()
    };
  });
};

var reverseQrFriendlyDerivationPath = function(qrFriendlyDerivationPath) {
  return `m/${qrFriendlyDerivationPath
    .replace(new RegExp("\\*", "g"), "/")
    .replace(new RegExp("\\-", "g"), "'")}`;
};

const getQrFriendlyDerivationPath = function(derivationPath) {
  return derivationPath
    .replace(new RegExp("^m/", "g"), "")
    .replace(new RegExp("/", "g"), "*")
    .replace(new RegExp("'", "g"), "-");
};

const infoFromCoinId = function(coinIdData) {
  coinIdData = coinIdData || "";
  // parses addressData fields in coinIdData

  const splitData = coinIdData.split("/");
  let type = splitData[0] || "";
  type = type.toLowerCase();
  coinIdData = splitData[1] || "";

  const parseOutputIndexData = inputData =>
    !inputData ? [] : inputData.split("+").map(Number);
  const parseInputDerivationData = inputData =>
    !inputData ? [] : inputData.split("+").map(reverseQrFriendlyDerivationPath);
  const parseInputValueData = inputData =>
    !inputData ? [] : inputData.split("+").map(Number);
  const parseSwpTxInputData = inputData => {
    const [type, address, hash, index, satValue] = inputData.split("*");

    return {
      type,
      address,
      hash,
      index: Number(index),
      satValue: Number(satValue)
    };
  };
  const parseSwpTxInputDataArr = inputData =>
    !inputData ? [] : inputData.split("+").map(parseSwpTxInputData);
  const parseSwpTxOutputData = inputData => {
    const [address, qrFriendlyDerivationPath, satValue] = inputData.split("+");

    return {
      address,
      derivationPath: reverseQrFriendlyDerivationPath(qrFriendlyDerivationPath),
      satValue: Number(satValue)
    };
  };

  const parse = cid => {
    const arr = cid.split(":");
    const ticker = arr[0].toLowerCase();
    const network = getNetworkFromTicker(ticker);

    if (arr.length < 3) {
      throw "Data not formatted correctly";
    }

    if (!network) {
      throw "Unsupported coin";
    }

    const head = {
      type,
      network,
      ticker: arr[0],
      ownerCheck: arr[1]
    };

    if(type == 'tx') {
      if( arr.length === 6) {
        return Object.assign(head, {
          inputDerivationPathArr: parseInputDerivationData(arr[2]),
          txHex: arr[3],
          changeOutputIndexArr: parseOutputIndexData(arr[4]),
          inputValueArr: parseInputValueData(arr[5]),
        });
      }

      if(arr.length === 7) {
        return Object.assign(head, {
          inputDerivationPathArr: parseInputDerivationData(arr[2]),
          txHex: arr[3],
          changeOutputIndexArr: parseOutputIndexData(arr[4]),
          inputValueArr: parseInputValueData(arr[5]),
          changeDerivationPathArr: parseInputDerivationData(arr[6]),
        });
      }
    }

    if (type == "pub" && arr.length == 3) {
      return Object.assign(head, {
        derivationPathArr: parseInputDerivationData(arr[2])
      });
    }

    if (type == "msg" && arr.length == 4) {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[2]),
        message: decodeURIComponent(arr[3])
      });
    }

    if (type == "sah" && arr.length == 4) {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[2]),
        message: decodeURIComponent(arr[3])
      });
    }

    if (type == "2fa" && arr.length == 4) {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[2]),
        message: decodeURIComponent(arr[3])
      });
    }

    if (type == "val" && arr.length == 3) {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[2])
      });
    }

    if (type == "swptx" && arr.length == 4) {
      return Object.assign(head, {
        outputInfo: parseSwpTxOutputData(arr[2]),
        inputInfoArr: parseSwpTxInputDataArr(arr[3])
      });
    }

    if (type == "swp" && arr.length == 3) {
      return head;
    }

    throw 'Incompatible data format. Please upgrade your wallet and vault to the latest version.';
  };

  const parsedData = parse(coinIdData);
  return parsedData;
};

/**
 * Gets information from a Raw TX Hex
 */
const infoFromTxHex = function(
  txHex,
  network,
  changeOutputIndexArr,
  inputValueArr
) {
  const tx = bitcoin.Transaction.fromHex(txHex, network);

  const mapOutputs = o => ({
    address: scriptToAddress(o.script, network),
    amount: o.value
  });

  const removeChange = (o, i) => !changeOutputIndexArr.includes(i);
  const removeExternal = (o, i) => !removeChange(o, i);

  const allOutputs = tx.outs.map(mapOutputs);
  const externalOutputs = allOutputs.filter(removeChange);
  const changeOutputs = allOutputs.filter(removeExternal);

  const allOutputTotal = allOutputs
    .map(o => o.amount)
    .reduce((sum, val) => sum + val, 0);
  const externalTotal = externalOutputs
    .map(o => o.amount)
    .reduce((sum, val) => sum + val, 0);
  const changeTotal = changeOutputs
    .map(o => o.amount)
    .reduce((sum, val) => sum + val, 0);

  const allInputTotal = inputValueArr.reduce((sum, val) => sum + val, 0);
  const fee = allInputTotal - allOutputTotal;

  return {
    allOutputs,
    externalOutputs,
    changeOutputs,
    allOutputTotal,
    externalTotal,
    changeTotal,
    allInputTotal,
    fee
  };
};

/**
 * infoFrominputInfoArr
 */
const infoFrominputInfoArr = function(inputInfoArr, outputInfo) {
  const total = inputInfoArr.reduce((a, { satValue }) => a + satValue, 0);

  return {
    inputs: inputInfoArr,
    receiveAddress: outputInfo.address,
    receiveDerivationPath: outputInfo.derivationPath,
    outputSat: Number(outputInfo.satValue),
    fee: Number(total - outputInfo.satValue),
    total: Number(total)
  };
};

/**
 * Signs TX Hex with mnemonic
 */
const signTx = function(
  unsignedTxHex,
  network,
  inputDerivationPathArr,
  inputValueArr,
  mnemonic
) {
  const tx = bitcoin.Transaction.fromHex(unsignedTxHex, network);
  const sendTx = bitcoin.TransactionBuilder.fromTransaction(tx, network);
  sendTx.maximumFeeRate = 5000;

  // because fromHex does not include P2WPKH input correctly we clear and add our inputs again here.
  const ins = sendTx.tx.ins.slice(0);
  sendTx.tx.ins = [];
  sendTx.inputs = [];
  sendTx.prevTxMap = {};

  inputDerivationPathArr.forEach((derivationPath, i) => {
    const input = ins[i];
    const hdNode = createHDNodeFromDerivationPath(
      derivationPath,
      network,
      mnemonic
    );

    getAddInputFunctionFromDerivation(derivationPath)(
      sendTx,
      input,
      input.sequence,
      hdNode
    );
  });

  inputDerivationPathArr.forEach((derivationPath, i) => {
    const hdNode = createHDNodeFromDerivationPath(
      derivationPath,
      network,
      mnemonic
    );
    getSignInputFunctionFromDerivation(derivationPath)(
      sendTx,
      i,
      hdNode,
      inputValueArr[i]
    );
  });

  const rawTx = sendTx
    .build()
    .toHex()
    .toUpperCase();
  return rawTx;
};

/**
 * Validate address
 */
const validateAddress = function(derivationPath, network, mnemonic) {
  const hdNode = createHDNodeFromDerivationPath(
    derivationPath,
    network,
    mnemonic
  );
  const derivedAddress = getAddressFunctionFromDerivation(derivationPath)(
    hdNode
  );

  return derivedAddress;
};

/**
 * Signs message
 */
const signMessage = function(message, derivationPath, network, mnemonic) {
  const hdNode = createHDNodeFromDerivationPath(
    derivationPath,
    network,
    mnemonic
  );
  const privateKey = hdNode.keyPair.d.toBuffer(32);
  const signature = bitcoinMessage.sign(
    message,
    privateKey,
    hdNode.keyPair.compressed,
    network
  );

  return signature.toString("base64");
};

/**
 * Gets Address from derivation path
 */
const getAddressFromDerivationPath = function(
  derivationPath,
  network,
  mnemonic
) {
  const derivedNode = createHDNodeFromDerivationPath(
    derivationPath,
    network,
    mnemonic
  );
  const derivedAddress = getAddressFunctionFromDerivation(derivationPath)(
    derivedNode
  );
  return derivedAddress;
};

const deriveAddressesFromWif = function(decryptedWif, network) {
  if (!decryptedWif) {
    return [];
  }

  const addresses = [];
  const node = bitcoin.ECPair.fromWIF(decryptedWif, network);

  network.supportedAddressTypes.forEach(addressType => {
    try {
      const addressInfo = {
        type: addressType,
        address: getAddressTypeInfo(addressType).addressFunction(node)
      };
      addresses.push(addressInfo);
    } catch (err) {
      // catches error cannot derive address. usually if node is uncompressed and trying to derive segwit
    }
  });

  return addresses;
};

const isBIP38Format = function(data) {
  return /^6P[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{56}$/.test(
    data
  );
};

const getECPairFromWif = function(data, network) {
  try {
    return bitcoin.ECPair.fromWIF(data, network);
  } catch (err) {
    return false;
  }
};

const decryptBIP38 = async function(encryptedWif, password, network, statusCb) {
  if (password === undefined) {
    return false;
  }

  try {
    const { privateKey, compressed } = await bip38.decrypt(
      encryptedWif,
      password,
      network,
      statusCb
    );
    const decryptedWif = wif.encode(
      network.wif,
      privateKey,
      compressed,
      network
    );
    return decryptedWif;
  } catch (err) {
    console.log({ err });
    return false;
  }
};

const isCompressed = node =>
  node.keyPair && node.keyPair.compressed ? true : node.compressed;

const parseSweepKeyData = async function(
  keyData,
  password,
  network,
  address,
  statusCb
) {
  let encryptedWif;
  let decryptedWif;

  if (isBIP38Format(keyData)) {
    encryptedWif = keyData;

    if (!bip38.verify(encryptedWif, address)) {
      throw "BIP38 verification error";
    }

    decryptedWif = await decryptBIP38(
      encryptedWif,
      password,
      network,
      statusCb
    );
  } else {
    decryptedWif = keyData;
  }

  if (!decryptedWif) {
    return {
      encryptedWif
    };
  }

  const keyPair = getECPairFromWif(decryptedWif, network);

  if (!keyPair) {
    throw "Could not parse keydata";
  }

  return {
    encryptedWif,
    decryptedWif,
    compressed: isCompressed(keyPair)
  };
};

const parseQsParamFromUrl = function(key, string) {
  if (!string) {
    return {};
  }

  const regexp = new RegExp(`(${key})=([^&]{1,})`, "i");
  const [, , value] = string.match(regexp) || [];

  if (!value) {
    return {};
  }

  return {
    [key]: decodeURIComponent(value)
  };
};

const parseSweepDataQs = function(qs) {
  if (!qs) {
    return {};
  }

  return {
    ...parseQsParamFromUrl("ticker", qs),
    ...parseQsParamFromUrl("message", qs),
    ...parseQsParamFromUrl("hint", qs),
    ...parseQsParamFromUrl("address", qs)
  };
};

const parseSweepDataInfo = function(sweepData) {
  const [, keyData, qs] = sweepData.match(/([^?]{1,})(\?.*)?/i) || [];
  const params = parseSweepDataQs(qs);

  return {
    keyData,
    params
  };
};

const parseSweepData = async function(sweepData, password, statusCb, network) {
  const { params, keyData } = parseSweepDataInfo(sweepData);

  if (params.ticker) {
    const privateKeyNetwork = getNetworkFromTicker(params.ticker);

    if(!privateKeyNetwork) {
      throw Error(
        "Unsupported network specified for private key"
      );
    }

    if(privateKeyNetwork !== network) {
      throw Error(
        "You are trying to sweep a " + privateKeyNetwork.title + " private key with a " + network.title + " wallet"
      );
    }
  }

  const { decryptedWif, encryptedWif, compressed } = await parseSweepKeyData(
    keyData,
    password,
    network,
    params.address,
    statusCb
  );

  const addresses = deriveAddressesFromWif(decryptedWif, network);

  return {
    decryptedWif,
    encryptedWif,
    compressed,
    addresses,
    params
  };
};

/**
 * Module exports...
 */
module.exports = function(coinIdData) {
  const info = infoFromCoinId(coinIdData);

  return {
    // general
    getInfo: () => info,
    getAddressFromDerivationPath: (derivationPath, mnemonic) =>
      getAddressFromDerivationPath(info.derivationPath, info.network, mnemonic),
    generateMnemonic: () => generateMnemonic(),
    getBasePublicKey: mnemonic => getBasePublicKey(info.network, mnemonic),
    verifyOwner: mnemonic =>
      verifyOwner(info.ownerCheck, info.network, mnemonic),
    verifyChangeOutputs: (changeOutputs, mnemonic) => verifyChangeOutputs(changeOutputs, info.changeDerivationPathArr, info.network, mnemonic),

    buildReturnUrl: ({ data, returnScheme, variant }) => {
      const getReturnScheme = () => {
        if (variant.toLowerCase() === "p2p") {
          return returnScheme.toUpperCase();
        }
        return returnScheme;
      };

      return `${getReturnScheme()}://${info.type.toUpperCase()}/${data}`;
    },

    // pub
    getPublicKey: mnemonic =>
      createPublicKeysFromDerivationPaths(
        info.derivationPathArr,
        info.network,
        mnemonic
      ),

    // tx
    getTxInfo: () =>
      infoFromTxHex(
        info.txHex,
        info.network,
        info.changeOutputIndexArr,
        info.inputValueArr
      ),
    signTx: mnemonic =>
      signTx(
        info.txHex,
        info.network,
        info.inputDerivationPathArr,
        info.inputValueArr,
        mnemonic
      ),

    // swp
    parseSweepData: (data, password, statusCb) =>
      parseSweepData(data, password, statusCb, info.network),

    getSweepReturnData: ({ addresses, compressed }) =>
      addresses
        .map(e => `${e.type}*${e.address}*${compressed ? "1" : "0"}`)
        .join("+"),

    // swptx
    createSweepTx: (mnemonic, { wif }) => {
      if (!wif) {
        throw "Sweeped private key missing";
      }

      const network = info.network;

      const swpTxInfo = infoFrominputInfoArr(
        info.inputInfoArr,
        info.outputInfo
      );
      const verifiedReceiveAddress = getAddressFromDerivationPath(
        swpTxInfo.receiveDerivationPath,
        network,
        mnemonic
      );

      if (verifiedReceiveAddress !== swpTxInfo.receiveAddress) {
        throw "Receive address does not belong to this Vault";
      }

      const node = bitcoin.ECPair.fromWIF(wif, network);

      const sendTx = new bitcoin.TransactionBuilder(info.network);

      const amountSat = swpTxInfo.outputSat;
      const feeSat = swpTxInfo.fee;
      const requiredSat = swpTxInfo.total;

      sendTx.addOutput(verifiedReceiveAddress, amountSat);

      swpTxInfo.inputs.forEach((input, i) => {
        const sequence = 0xffffffff;
        const { addInputFunction } = getAddressTypeInfo(input.type);
        addInputFunction(sendTx, input, sequence, node);
      });

      swpTxInfo.inputs.forEach((input, i) => {
        const { signInputFunction } = getAddressTypeInfo(input.type);
        signInputFunction(sendTx, i, node, input.satValue);
      });

      return sendTx
        .build()
        .toHex()
        .toUpperCase();
    },

    getSwpTxInfo: () =>
      infoFrominputInfoArr(info.inputInfoArr, info.outputInfo),

    // val
    validateAddress: mnemonic =>
      validateAddress(info.derivationPath, info.network, mnemonic),

    // msg
    signMessage: mnemonic =>
      signMessage(info.message, info.derivationPath, info.network, mnemonic),

    // get requested data based on type
    getReturnData(mnemonic, extraData) {
      return new Promise((resolve, reject) => {
        if (info.type === "sah") {
          // simple auth skips ownercheck...
          return resolve(info.message);
        }

        if (info.type === "swp") {
          return resolve(this.getSweepReturnData(extraData));
        }

        if (this.verifyOwner(mnemonic)) {
          switch (info.type) {
            case 'tx':
              var txInfo = this.getTxInfo(info);
              if(this.verifyChangeOutputs(txInfo.changeOutputs, mnemonic)) {
                return resolve(this.signTx(mnemonic));
              }
            break;
            case "swptx":
              return resolve(this.createSweepTx(mnemonic, extraData));
            case "val":
              return resolve(this.validateAddress(mnemonic));
            case "msg":
              return resolve(this.signMessage(mnemonic));
            case "2fa":
              return resolve(this.signMessage(mnemonic));
            case "pub":
              return resolve(
                this.getPublicKey(mnemonic)
                  .map(
                    p =>
                      `${getQrFriendlyDerivationPath(p.derivationPath)}$${
                        p.publicKey
                      }`
                  )
                  .join("+")
              );
          }
        }
      });
    }
  };
};
