"use strict"

/**
* Lib for CoinID
*/

import bip39 from 'react-native-bip39'
const bitcoin        = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');
const md5            = require('md5');
import { getAddressFunctionFromDerivation, getSignInputFunctionFromDerivation } from 'coinid-address-types'

const supportedNetworks = {
  'xmy': bitcoin.networks.myriad,
  'btc': bitcoin.networks.bitcoin,
  'tbtc': bitcoin.networks.testnet
}

/**
 * Generates Mnemonic based on bip39
 */
var generateMnemonic = function() {
  try {
    return bip39.generateMnemonic(128) // default to 128 
  } catch(e) {
    return false
  }
}

/**
 * Retrieves network parameters from ticker string
 */
var getNetworkFromTicker = function(ticker) {
  return supportedNetworks[ticker.toLowerCase()];
};

/**
 * Gets Address from script
 */
var scriptToAddress = function(script, network) {
  return bitcoin.address.fromOutputScript(script, network);
}

var getBasePublicKey = function(network, mnemonic) {
  var hdNode = getBaseHDNode(network, mnemonic);
  return hdNode.neutered().toBase58();
}

var getHdNodeFromPublicKey = function(network, pubKey) {
  var hdNode = bitcoin.HDNode.fromBase58(pubKey, network)
  return hdNode;
}

var verifyOwner = function(ownerCheck, network, mnemonic) {
  if(ownerCheck) {
    var hdNode = getBaseHDNode(network, mnemonic);
    var { derivationPath, address } = parseOwnerCheck(ownerCheck);
    var derivedNode = hdNode.derivePath(derivationPath);

    var derivedAddress = getAddressFunctionFromDerivation(derivationPath)(derivedNode);
    var shortenedAddress = derivedAddress.substr(0, address.length);

    if(shortenedAddress.toUpperCase() !== address.toUpperCase()) {
      throw('Wallet not created from this COINiD');
    }
  }

  return true;
}

var parseOwnerCheck = function(ownerCheck) {
  var splitData = ownerCheck.split('+');
  var derivationPath = reverseQrFriendlyDerivationPath(splitData[0]);
  var address = splitData[1];

  return {
    derivationPath,
    address
  }
}

var cachedHDNodeMap = {};

var getCachedHDNodeKey = (derivationPath, network, mnemonic) => {
  return md5(derivationPath + network.wif + mnemonic);
}

var getCachedHDNode = (derivationPath, network, mnemonic) => {
  var cacheKey = getCachedHDNodeKey(derivationPath, network, mnemonic);
  return cachedHDNodeMap[cacheKey];
}

var setCachedHDNode = (hdNode, derivationPath, network, mnemonic) => {
  var cacheKey = getCachedHDNodeKey(derivationPath, network, mnemonic);
  cachedHDNodeMap[cacheKey] = hdNode;
}

/**
 * Creates HDNode from mnemonic
 */
var getBaseHDNode = function(network, mnemonic) {
  var hdNode = getCachedHDNode('m', network, mnemonic);

  if(hdNode === undefined) {
    hdNode = bitcoin.HDNode.fromSeedBuffer(
      bip39.mnemonicToSeed(mnemonic),
      network 
    );
    setCachedHDNode(hdNode, 'm', network, mnemonic);
  }

  return hdNode;
}

/**
 * Gets keyPair from derivation path and Mnemonic
 */
var createHDNodeFromDerivationPath = function(derivationPath, network, mnemonic) {
  var cachedHDNode = getCachedHDNode(derivationPath, network, mnemonic);
  if(cachedHDNode !== undefined) {
    return cachedHDNode;
  }

  var currentHDNode = getBaseHDNode(network, mnemonic);

  var splitPath = derivationPath.split('/');
  if (splitPath[0] === 'm') {
    splitPath = splitPath.slice(1);
  }

  for (var i = 0; i < splitPath.length; i++) {
    var path = splitPath[i];
    var fullPath = 'm/'+splitPath.slice(0, i+1).join('/');

    var cachedHDNode = getCachedHDNode(fullPath, network, mnemonic);
    if(cachedHDNode === undefined) {
      currentHDNode = currentHDNode.derivePath(path);
      setCachedHDNode(currentHDNode, fullPath, network, mnemonic);
    }
    else {
      currentHDNode = cachedHDNode;
    }
  }
  return currentHDNode;
}



/**
 * Creates Public Keys for purposeArr which can derive chain and index. This is transfered to the wallet to set up an account..
 */
var createPublicKeysFromDerivationPaths = function(derivationPathArr, network, mnemonic) {
  return derivationPathArr.map(derivationPath => {
    var hdNode = createHDNodeFromDerivationPath(derivationPath, network, mnemonic);
    
    return {
      derivationPath: derivationPath,
      publicKey: hdNode.neutered().toBase58()
    }
  });
}

var reverseQrFriendlyDerivationPath = function(qrFriendlyDerivationPath) {
  return 'm/'+qrFriendlyDerivationPath.replace(new RegExp('\\*', 'g'), '/').replace(new RegExp('\\-', 'g'), '\'');
}

var getQrFriendlyDerivationPath = function(derivationPath) {
  return derivationPath
  .replace(new RegExp('^m\/', 'g'), '')
  .replace(new RegExp('\/', 'g'), '*')
  .replace(new RegExp('\'', 'g'), '-');
}

/** - coinData innehåller fee också då vi inte kan ta reda på detta offline annars.. kanske unsafe... om coinid är online så bör vi kanske hämta fee från blockchain
 *                                       [inputDerivationData]                                        [changeOutputIndexData]
 * Structure of signTx = [type]/[ticker].[derivationPath+derivationPath+derivationPath].[unsignedHex].[index+index+index].[fee]
 * Structure of getPubKey = [type]/[ticker].[derivationPath+derivationPath] // vid skapandet av wallet..
 * Structure of signMsg = [type]/[ticker].[derivationPath].message
 *
 * derivationPath:
 * seperator: *
 * hardened indicator: -
 * example: 44-*90-*0-*1*2 = 44'/90'/0'/1/2
 *
 * types = tx, pub, msg
 *
 */
var infoFromCoinId = function(coinIdData) {
  coinIdData = coinIdData || '';
  // parses addressData fields in coinIdData
  

  var splitData = coinIdData.split('/');
  var type = splitData[0] || '';
  type = type.toLowerCase();
  coinIdData = splitData[1] || '';

  var parseOutputIndexData = inputData => !inputData ? [] : inputData.split('+').map(Number);
  var parseInputDerivationData = inputData => !inputData ? [] : inputData.split('+').map(reverseQrFriendlyDerivationPath);
  var parseInputValueData = inputData => !inputData ? [] : inputData.split('+').map(Number);

  var parse = cid => {
    var arr = cid.split(':');
    var ticker = arr[0].toLowerCase();
    var network = getNetworkFromTicker(ticker);

    if(arr.length < 3) {
      throw('Data not formatted correctly');
    }

    if(!network) {
      throw('Unsupported coin');
    }

    var head = {
      type: type,
      network: network,
      ticker: arr[0],
      ownerCheck: arr[1]
    }

    if(type == 'tx' && arr.length == 6) {
      return Object.assign(head, {
        inputDerivationPathArr: parseInputDerivationData(arr[2]),
        txHex: arr[3],
        changeOutputIndexArr: parseOutputIndexData(arr[4]),
        inputValueArr: parseInputValueData(arr[5]),
      });
    }

    if(type == 'pub' && arr.length == 3) {
      return Object.assign(head, {
        derivationPathArr: parseInputDerivationData(arr[2])
      });
    }

    if(type == 'msg' && arr.length == 4) {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[2]),
        message: decodeURIComponent(arr[3]),
      });
    }

    if(type == '2fa' && arr.length == 4) {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[2]),
        message: decodeURIComponent(arr[3]),
      });
    }

    if(type == 'val' && arr.length == 3) {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[2]),
      });
    }

    return head;
  }

  var parsedData = parse(coinIdData);

  return parsedData;
}

/**
 * Gets information from a Raw TX Hex
 */
var infoFromTxHex = function(txHex, network, changeOutputIndexArr, inputValueArr) {
  var tx = bitcoin.Transaction.fromHex(txHex);

  var mapOutputs = o => ({
    address: scriptToAddress(o.script, network),
    amount: o.value
  });

  var removeChange = (o, i) => !changeOutputIndexArr.includes(i);
  var removeExternal = (o, i) => !removeChange(o, i);
  
  var allOutputs = tx.outs.map(mapOutputs);
  var externalOutputs = allOutputs.filter(removeChange);
  var changeOutputs = allOutputs.filter(removeExternal);

  var allOutputTotal = allOutputs.map(o => o.amount).reduce((sum, val) => sum+val, 0);
  var externalTotal = externalOutputs.map(o => o.amount).reduce((sum, val) => sum+val, 0);
  var changeTotal = changeOutputs.map(o => o.amount).reduce((sum, val) => sum+val, 0);

  var allInputTotal = inputValueArr.reduce((sum, val) => sum+val, 0);
  var fee = allInputTotal - allOutputTotal;

  return {
    allOutputs,
    externalOutputs,
    changeOutputs,
    allOutputTotal,
    externalTotal,
    changeTotal,
    allInputTotal,
    fee
  }
}

/**
 * Signs TX Hex with mnemonic
 */
var signTx = function(unsignedTxHex, network, inputDerivationPathArr, inputValueArr, mnemonic) {

  var tx = bitcoin.Transaction.fromHex(unsignedTxHex);
  var sendTx = bitcoin.TransactionBuilder.fromTransaction(tx, network);
  sendTx.maximumFeeRate = 5000;

  inputDerivationPathArr.forEach((derivationPath, i) => {
    var hdNode = createHDNodeFromDerivationPath(derivationPath, network, mnemonic);
    getSignInputFunctionFromDerivation(derivationPath)(sendTx, i, hdNode, inputValueArr[i]);
  });

  let rawTx = sendTx.build().toHex();
  return rawTx;
}

/**
 * Validate address
 */
var validateAddress = function(derivationPath, network, mnemonic) {
  var hdNode = createHDNodeFromDerivationPath(derivationPath, network, mnemonic);
  var derivedAddress = getAddressFunctionFromDerivation(derivationPath)(hdNode);

  return derivedAddress;
}

/**
 * Signs message
 */
var signMessage = function(message, derivationPath, network, mnemonic) {
  var hdNode = createHDNodeFromDerivationPath(derivationPath, network, mnemonic);
  var privateKey = hdNode.keyPair.d.toBuffer(32);
  var signature = bitcoinMessage.sign(message, privateKey, hdNode.keyPair.compressed, network.messagePrefix);

  return signature.toString('base64');
}

/**
 * Gets Address from derivation path
 */
var getAddressFromDerivationPath = function(derivationPath, network, mnemonic) {
  var hdNode = createHDNodeFromDerivationPath(derivationPath, network, mnemonic);
  return hdNode.getAddress();
}

/**
 * Module exports...
 */
module.exports = function(coinIdData) {
  var info = infoFromCoinId(coinIdData);

  return {
    // general
    getInfo: () => info,
    getAddressFromDerivationPath: (derivationPath, mnemonic) => getAddressFromDerivationPath(info.derivationPath, info.network, mnemonic),
    generateMnemonic: () => generateMnemonic(),
    getBasePublicKey: (mnemonic) => getBasePublicKey(info.network, mnemonic),
    verifyOwner: (mnemonic) => verifyOwner(info.ownerCheck, info.network, mnemonic),

    // pub
    getPublicKey: (mnemonic) => createPublicKeysFromDerivationPaths(info.derivationPathArr, info.network, mnemonic),

    // tx
    getTxInfo: () => infoFromTxHex(info.txHex, info.network, info.changeOutputIndexArr, info.inputValueArr),
    signTx: (mnemonic) => signTx(info.txHex, info.network, info.inputDerivationPathArr, info.inputValueArr, mnemonic),

    // val
    validateAddress: (mnemonic) => validateAddress(info.derivationPath, info.network, mnemonic),

    // msg
    signMessage: (mnemonic) => signMessage(info.message, info.derivationPath, info.network, mnemonic),

    // get requested data based on type
    getReturnData: function (mnemonic) {
      return new Promise((resolve, reject) => {
        if(info.type === 'sah') { // simple auth skips ownercheck...
          return resolve(info.message);
        }

        if(this.verifyOwner(mnemonic)) {
          switch(info.type) {
            case 'tx': return resolve(this.signTx(mnemonic));
            case 'val': return resolve(this.validateAddress(mnemonic));
            case 'msg': return resolve(this.signMessage(mnemonic));
            case '2fa': return resolve(this.signMessage(mnemonic));
            case 'pub': return resolve(this.getPublicKey(mnemonic).map((p) => getQrFriendlyDerivationPath(p.derivationPath) + '$' + p.publicKey).join('+'));
          }
        }
      })
    },
  }
}