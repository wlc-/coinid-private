"use strict"

/**
* Lib for CoinID
*/

const bip39          = require('bip39');
const bitcoin        = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');

const supportedNetworks = {
  'xmy': bitcoin.networks.myriad,
  'btc': bitcoin.networks.bitcoin
}

/**
 * Generates Mnemonic based on bip39
 */
var generateMnemonic = function() {
  return bip39.generateMnemonic();
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
  return derivationPathArr.map(derivationPath => ({
    derivationPath: derivationPath,
    publicKey: createHDNodeFromDerivationPath(derivationPath, network, mnemonic).neutered().toBase58()
  }));
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
    var arr = cid.split('.');
    var network = getNetworkFromTicker(arr[0]);

    var head = {
      type: type,
      network: network,
      ticker: arr[0]
    }

    if(type == 'tx') {
      return Object.assign(head, {
        inputDerivationPathArr: parseInputDerivationData(arr[1]),
        txHex: arr[2],
        changeOutputIndexArr: parseOutputIndexData(arr[3]),
        fee: Number(arr[4])
      });
    }

    if(type == 'pub') {
      return Object.assign(head, {
        derivationPathArr: parseInputDerivationData(arr[1])
      });
    }

    if(type == 'msg') {
      return Object.assign(head, {
        derivationPath: reverseQrFriendlyDerivationPath(arr[1]),
        message: decodeURIComponent(arr[2]),
      });
    }

    return head;
  }

  return parse(coinIdData);
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
    sendTx.sign(i, createHDNodeFromDerivationPath(derivationPath, network, mnemonic));
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

    // pub
    getPublicKey: (mnemonic) => createPublicKeysFromDerivationPaths(info.derivationPathArr, info.network, mnemonic),

    // tx
    getTxInfo: () => infoFromTxHex(info.txHex, info.network, info.changeOutputIndexArr, info.fee),
    signTx: (mnemonic) => signTx(info.txHex, info.network, info.inputDerivationPathArr, mnemonic),

    // msg
    signMessage: (mnemonic) => signMessage(info.message, info.derivationPath, info.network, mnemonic),

    // get requested data based on type
    getReturnData: function (mnemonic) {
      var data = '';

      if(info.type == 'tx') {
        data = this.signTx(mnemonic);
      }
      if(info.type == 'msg') {
        data = this.signMessage(mnemonic);
      }
      if(info.type == 'pub') {
        var publicKeys = this.getPublicKey(mnemonic);
        data = publicKeys.map((p) => getQrFriendlyDerivationPath(p.derivationPath) + '$' + p.publicKey).join('+');
      }

      return data;
    },
  }
}
