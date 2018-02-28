"use strict"

/**
* Lib for CoinID
*/

import bip39 from 'react-native-bip39'
const bitcoin        = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');

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
  return supportedNetworks[ticker];
};

/**
 * Gets Address from script
 */
var scriptToAddress = function(script, network) {
  return bitcoin.address.fromOutputScript(script, network);
}

/**
 * Creates HDNode from mnemonic
 */
var getBaseHDNode = function(network, mnemonic) {
  var hdNode = bitcoin.HDNode.fromSeedBuffer(
    bip39.mnemonicToSeed(mnemonic),
    network 
  );

  return hdNode;
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

    var derivedAddress = derivedNode.getAddress();
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

/**
 * Gets keyPair from derivation path and Mnemonic
 */
var createHDNodeFromDerivationPath = function(derivationPath, network, mnemonic) {
  var baseHDNode = getBaseHDNode(network, mnemonic);
  var derivedHDNode = baseHDNode.derivePath(derivationPath);

  return derivedHDNode;
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
  coinIdData = coinIdData.toLowerCase();

  var splitData = coinIdData.split('/');
  var type = splitData[0] || '';
  coinIdData = splitData[1] || '';

  var parseOutputIndexData = inputData => !inputData ? [] : inputData.split('+').map(Number);
  var parseInputDerivationData = inputData => !inputData ? [] : inputData.split('+').map(reverseQrFriendlyDerivationPath);

  var parse = cid => {
    var arr = cid.split(':');
    var network = getNetworkFromTicker(arr[0]);

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
        fee: Number(arr[5])
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

    return head;
  }

  var parsedData = parse(coinIdData);

  return parsedData;
}

/**
 * Gets information from a Raw TX Hex
 */
var infoFromTxHex = function(txHex, network, changeOutputIndexArr, fee) {
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

  var allTotal = allOutputs.map(o => o.amount).reduce((sum, val) => sum+val, 0);
  var externalTotal = externalOutputs.map(o => o.amount).reduce((sum, val) => sum+val, 0);
  var changeTotal = changeOutputs.map(o => o.amount).reduce((sum, val) => sum+val, 0);

  return {
    allOutputs,
    externalOutputs,
    changeOutputs,
    allTotal,
    externalTotal,
    changeTotal,
    fee
  }
}

/**
 * Signs TX Hex with mnemonic
 */
var signTx = function(unsignedTxHex, network, inputDerivationPathArr, mnemonic) {
  var tx = bitcoin.Transaction.fromHex(unsignedTxHex);
  var sendTx = bitcoin.TransactionBuilder.fromTransaction(tx, network);
  
  inputDerivationPathArr.forEach((derivationPath, i) => {
    var hdNode = createHDNodeFromDerivationPath(derivationPath, network, mnemonic);
    sendTx.sign(i, hdNode);
  });

  return sendTx.build().toHex().toUpperCase();
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
    getTxInfo: () => infoFromTxHex(info.txHex, info.network, info.changeOutputIndexArr, info.fee),
    signTx: (mnemonic) => signTx(info.txHex, info.network, info.inputDerivationPathArr, mnemonic),

    // msg
    signMessage: (mnemonic) => signMessage(info.message, info.derivationPath, info.network, mnemonic),

    // get requested data based on type
    getReturnData: function (mnemonic) {
      return new Promise((resolve, reject) => {
        if(this.verifyOwner(mnemonic)) {
          switch(info.type) {
            case 'tx': return resolve(this.signTx(mnemonic));
            case 'msg': return resolve(this.signMessage(mnemonic));
            case 'pub': return resolve(this.getPublicKey(mnemonic).map((p) => getQrFriendlyDerivationPath(p.derivationPath) + '$' + p.publicKey).join('+'));
          }
        }
      })
    },
  }
}
