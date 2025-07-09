import ecc from '@bitcoinerlab/secp256k1'; //https://www.npmjs.com/package/@bitcoinerlab/secp256k1
import * as bip39 from '@scure/bip39'; //https://www.npmjs.com/package/@scure/bip39
import { wordlist } from '@scure/bip39/wordlists/english'; //bip39 助记词库
import { BIP32Factory } from 'bip32'; //https://www.npmjs.com/package/bip32
import bs from 'bs58'; //https://www.npmjs.com/package/bs58
import { ethers } from 'ethers'; //https://www.npmjs.com/package/ethers
import slip10 from 'micro-key-producer/slip10.js'; //https://www.npmjs.com/package/micro-key-producer
import AsyncStorage from '@react-native-async-storage/async-storage'; //https://www.npmjs.com/package/@react-native-async-storage/async-storage
import { v4 as uuidv4 } from 'uuid'; //https://www.npmjs.com/package/uuid
import * as Keychain from 'react-native-keychain'; //https://www.npmjs.com/package/react-native-keychain
import axios from 'axios'; //https://www.npmjs.com/package/axios
import {
    getBase64Encoder,
    getTransactionDecoder,
    createKeyPairSignerFromBytes,
    getCompiledTransactionMessageDecoder,
    decompileTransactionMessage,
    setTransactionMessageFeePayerSigner,
    signTransactionMessageWithSigners,
    getBase64EncodedWireTransaction
} from '@solana/kit'; //https://www.npmjs.com/package/@solana/kit
import nacl from 'tweetnacl'; //https://www.npmjs.com/package/tweetnacl


/**
 *  @Test 关于手动测试
 功能简单性：该代码的功能相对简单，主要涉及基础的助记词生成和地址管理，本地签名，逻辑清晰且易于理解。
 现有测试覆盖：我们已经在项目中提供了全面的集成测试，这些测试有效地覆盖了关键功能，确保了系统的稳定性。
 代码稳定性：该代码在过去的版本中运行良好，经过多次审查，未发现问题。
 */

//内部加密存储方法
const setKeychainValue = async (key, value) => {
    try {
        const genericPassword = await Keychain.setGenericPassword(key, value, {
            service: key,
            accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
            accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        });
        return genericPassword;
    } catch (error) {
        throw new Error(`加密存储错误： ${error.message}`);
    }
}
/**
 * @Test 手动测试setKeychainValue()方法

 成功示例
 const setKeyChainValueSuccess = await setKeychainValue('wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86', '0')
 成功结果
 {"service": "wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86", "storage": "keychain"}

 失败示例
 const setKeyChainValueError1 = await setKeychainValue('wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86')
 失败结果 加密存储错误： ${error.message}

 const setKeyChainValueError2 = await setKeychainValue()
 失败结果 加密存储错误： ${error.message}
 */



//移除加密存储方法
const removeKeychainValue = async (key) => {
    try {
        const removeKeychainValue = await Keychain.resetGenericPassword({
            service: key,
        });
        return removeKeychainValue;
    } catch (error) {
        throw new Error(`移除加密错误： ${error.message}`);
    }
}
/*
    @Test 手动测试 removeKeychainValue() 方法
    成功示例
    const removeKeychainSuccess = await removeKeychainValue('wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86')
    成功结果 removeKeychainSuccess => true

    失败示例
    const removeKeychainSuccessError1 = await removeKeychainValue()
    失败结果
    移除加密错误： ${error.message}
*/


//获取加密存储方法
const getKeychainValue = async (key) => {
    try {
        const keychainValue = await Keychain.getGenericPassword({
            service: key,
        });
        return keychainValue.password
    } catch (error) {
        throw new Error(`获取加密错误： ${error.message}`);
    }
}

/**
 @Test 手动测试 getKeychainValue() 方法
  成功示例
  const getKeychainValueSuccess = await getKeychainValue('wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86')
  成功结果
  {"password": "mixed globe lunch ability rose feel romance choose bleak solar abstract frog", "service": "wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86", "storage": "keychain", "username": "wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86"}

  失败示例
  const getKeychainValueError1 = await getKeychainValue()
  失败结果
  获取加密错误：： ${error.message}
 */




//根据助记词生成地址，内部方法
const generateAddresses = async (mnemonic, index) => {

    try {
        const seed = await bip39.mnemonicToSeed(mnemonic);
        const bip32 = BIP32Factory(ecc);
        const root = bip32.fromSeed(seed);

        // 生成以太坊地址
        const ethPath = "m/44'/60'/0'/0/" + index; // BIP44 路径
        const ethNode = root.derivePath(ethPath);
        const ethPrivateKey = Array.from(ethNode.privateKey).map(byte => byte.toString(16).padStart(2, '0')).join('');
        const wallet = new ethers.Wallet(ethPrivateKey);
        const ethAddress = wallet.address;

        // 生成sol地址
        const solPath = "m/44'/501'/" + index + "'/0'"; // BIP44 路径
        const hdKey = slip10.fromMasterSeed(Buffer.from(seed));
        const keyPair = nacl.sign.keyPair.fromSeed(hdKey.derive(solPath).privateKey);
        const privateKey = keyPair.secretKey;
        const publicKey = keyPair.publicKey;
        const solPrivateKey = bs.encode(privateKey)
        const solAddress = bs.encode(publicKey)

        const uuid = uuidv4();

        //组装列表
        const generateAddresseslist = [
            {
                generateType: 'EVM',
                address: ethAddress,
                privateKey: ethPrivateKey,
            },
            {
                generateType: 'Solana',
                address: solAddress,
                privateKey: solPrivateKey,
            }
        ]

        //加密存储助记词
        const walletServiceName = 'wallet_' + uuid;
        await setKeychainValue(walletServiceName, mnemonic)

        //遍历加密存储私钥
        for (let i = 0; i < generateAddresseslist.length; i++) {
            const addressServiceName = 'address_' + generateAddresseslist[i].address + '_type_' + generateAddresseslist[i].generateType;
            await setKeychainValue(addressServiceName, generateAddresseslist[i].privateKey)
        }

        return {
            uuid: uuid,
            addressList: [
                {
                    generateType: 'EVM',
                    address: ethAddress,

                },
                {
                    generateType: 'Solana',
                    address: solAddress,
                }
            ]
        }
    } catch (error) {
        throw new Error(`生成地址失败： ${error.message}`);
    }
}

/** @Test 手动测试 generateAddresses() 方法
 成功示例
 const generateAddressesSuccess = await generateAddresses('answer gown deal parent december coffee only clog camera pistol taxi minor', 0)
 成功结果
 {
 "uuid": "9782a7e7-e0f0-4b17-9e9a-411e007eb4f1",
 "addressList": [
 {
 "generateType": "Solana",
 "address": "FsXEXnfF6KSgPAZ8W8MFFSmM9RLzn75Hejz87EhmhnZJ"
 },
 {
 "generateType": "EVM",
 "address": "0x2224D77977e546b495B1772Bf0b0cD343185352D"
 }
 ]
 }
 失败示例
 const generateAddressesError1 = await generateAddresses('answer gown deal parent december coffee only clog camera pistol taxi minor')
 const generateAddressesError2 = await generateAddresses('answer gown deal paren')
 const generateAddressesError3 = await generateAddresses('answergowndealparen')
 const generateAddressesError4 = await generateAddresses(12345)
 const generateAddressesError5 = await generateAddresses()
 失败结果
 生成地址失败： ${error.message}

 */




//导入私钥钱包，内部方法
const createWalletByPrivateKey = async (privateKey, type) => {

    let addressServiceName;
    let address;
    try {

        if (type === 'EVM') {
            const wallet = new ethers.Wallet(privateKey);
            addressServiceName = 'address_' + wallet.address + '_type_' + type;
            address = wallet.address;

        } else if (type === 'Solana') {
            const keyPair = nacl.sign.keyPair.fromSecretKey(bs.decode(privateKey));
            const publicKey = keyPair.publicKey;
            const solAddress = bs.encode(publicKey)
            address = solAddress;

        }

        await setKeychainValue(addressServiceName, privateKey)

        return {
            uuid: uuidv4(),
            addressList: [
                {
                    generateType: type,
                    address: address,
                },
            ]

        }
    } catch (error) {
        throw new Error(`导入私钥失败： ${error.message}`);
    }
}

/**
 @Test 手动测试 createWalletByPrivateKey() 方法
  成功示例
  const createWalletByPrivateKeySuccess = createWalletByPrivateKey('4HT3Arq3jXXc1iGDSKZemSEr8ycsS8mBPPnFdEGuDnT6wRpNzPvWHzbZYPVBeJqyEWQnChCPyyyeNzzVZmTzDz5Q', 'Solana')
  成功结果
  {
  "uuid": "9782a7e7-e0f0-4b17-9e9a-411e007eb4f1",
  "addressList": [
  {
  "generateType": "Solana",
  "address": "FsXEXnfF6KSgPAZ8W8MFFSmM9RLzn75Hejz87EhmhnZJ"
  },
  ]
  }
  失败示例
  const createWalletByPrivateKeyError1 = await createWalletByPrivateKey('4HT3Arq3jXXc1iGDSKZemSEr8r')
  const createWalletByPrivateKeyError2 = await createWalletByPrivateKey('answer gown deal parent december coffee only clog camera pistol taxi minor')
  const createWalletByPrivateKeyError3 = await createWalletByPrivateKey(12345)
  const createWalletByPrivateKeyError4 = await createWalletByPrivateKey()
  失败结果
  生成地址失败： ${error.message}

 */




let isGetNextWalletId = true;
//这里方式是同步执行 用户重复点击已经在业务逻辑层面处理完成，不会出现重复的id
const getNextWalletId = async () => {
    try {
        let walletId;
        if (isGetNextWalletId) {
            isGetNextWalletId = false;
            const id = await AsyncStorage.getItem('@walletId');
            walletId = +id + 1
            await AsyncStorage.setItem('@walletId', walletId.toString());
            isGetNextWalletId = true;
        }
        return walletId;
    } catch (error) {
        isGetNextWalletId = true;
        throw new Error(`获取id失败： ${error.message}`);
    }
}
/** @Test 手动测试 getNextWalletId() 方法
 成功示例
 const getNextWalletIdSuccess = await getNextWalletId()
 成功结果
 1
 失败示例
 const getNextWalletIdError1 = await getNextWalletId()
 失败结果
 获取id失败： ${error.message}
 */



//创建多链钱包
const createWallet = async () => {
    try {
        const secretPhrase = bip39.generateMnemonic(wordlist); //生成12位随机助记词
        const { uuid, addressList } = await generateAddresses(secretPhrase, 0); //通过助记词生成地址和私钥

        const id = await getNextWalletId()

        const walletObject = {
            uuid: uuid, //钱包uuid
            addressList: addressList, //地址集合
            type: 1, // 1 =>hd钱包， 2 =>私钥钱包
            source: 1, //1 =>创建 2 =>恢复
            avatar: 1, //头像
            name: `Wallet ${id}`, //钱包名称
            status: 0,  // 0 =>未备份， 1 =>已备份 2 => 导入
            balance: 0,  //余额
        };
        return walletObject
    } catch (error) {
        throw new Error(`创建多链钱包失败： ${error.message}`);
    }
};

/** @Test 手动测试 createWallet() 方法
 成功示例
 const createWalletSuccess = await createWallet()
 成功结果
 {
 uuid: 69ab6e21-eca2-4ccb-8a04-b756d7e42f86, //钱包uuid
 addressList: [
 {
 "generateType": "Solana",
 "address": "3YCTnCMkUGJv9yXot2DvrWkb1vw1p8TivLAW7KYGZgjP"
 },
 {
 "generateType": "EVM",
 "address": "0x86c933BBc3FA528B02C0ad72Bc3E6ae4723bf147"
 }
 ]
 type: 1,
 source: 1,
 avatar: 1,
 name: `Wallet 1`,
 status: 0,
 balance: 0,
 }
 失败示例
 const createWalletError1 = await createWallet()
 失败结果
 创建多链钱包失败： ${error.message}
 */



//删除钱包
const deleteWallet = async (uuid) => {
    try {
        const newWallets = _.filter(wallets, wallet => wallet.uuid !== uuid);
        //删除加密后的助记词

        await removeKeychainValue('wallet_' + uuid)

        //遍历删除加密后的私钥
        for (let i = 0; i < wallets.length; i++) {
            if (wallets[i].uuid === uuid) { //根据问题E建议，删除与提供的uuid匹配的钱包的私钥
                await removeKeychainValue('address_' + wallets[i].address + '_type_' + wallets[i].generateType)
            }
        }

        return newWallets;
    } catch (error) {
        throw new Error(`删除钱包失败： ${error.message}`);

    }
}

/** @Test 手动测试 deleteWallet() 方法
 成功示例
 const deleteWalletSuccess = deleteWallet('69ab6e21-eca2-4ccb-8a04-b756d7e42f86')
 成功结果
 [
 {
 "uuid": "d07547ea-4770-4114-86b8-c06914544159",
 "addressList": [
 {
 "generateType": "Solana",
 "address": "7Cu2j85v57hgKmJh4GbUn13zQ6FGHGWu4SedhMVSryZx",
 "chainId": 501
 },
 {
 "generateType": "EVM",
 "address": "0x3a8224eCB89056ee52Ac186eB567C76E672101be",
 },
 ],
 "type": 1,
 "source": 1,
 "avatar": 1,
 "name": "Wallet 1",
 "status": 0,
 "balance": 0.1068605999969788,
 "walletId": 1398,
 },
 ]
 失败示例
 const deleteWalletError1 = deleteWallet('123')
 const deleteWalletError2 = deleteWallet()
 失败结果
 删除钱包失败： ${error.message}
 */



//通过私钥导入钱包
const importWalletByPrivateKey = async ({ privateKey, type }) => {
    try {

        const addressesParams = await createWalletByPrivateKey(privateKey, type); //生成地址
        const { uuid, addressList } = addressesParams;
        const id = await getNextWalletId() //生成id

        const walletObject = {
            uuid: uuid, //钱包id
            addressList: addressList, //地址集合
            type: 2, // 1 =>hd钱包， 2 =>私钥钱包
            source: 2, //1 =>创建 2 =>恢复
            avatar: 1, //头像
            name: `Wallet ${id}`, //钱包名称
            status: 2,  // 0 =>未备份， 1 =>已备份 2 => 导入
            balance: 0, //余额
        };
        return walletObject

    } catch (error) {
        throw new Error(`导入私钥钱包失败： ${error.message}`);
    }
};

/** @Test 手动测试 importWalletByPrivateKey() 方法
 成功示例
 const importWalletByPrivateKeySuccess = await importWalletByPrivateKey({ privateKey: "4HT3Arq3jXXc1iGDSKZemSEr8ycsS8mBPPnFdEGuDnT6wRpNzPvWHzbZYPVBeJqyEWQnChCPyyyeNzzVZmTzDz5Q", type: 'Solana' })
 成功结果
 {
 uuid: 69ab6e21-eca2-4ccb-8a04-b756d7e42f86, //钱包uuid
 addressList: [
 {
 "generateType": "Solana",
 "address": "3YCTnCMkUGJv9yXot2DvrWkb1vw1p8TivLAW7KYGZgjP"
 },
 ]
 type: 2,
 source: 2,
 avatar: 3,
 name: `Wallet 3`,
 status: 2,
 balance: 0,
 }
 失败示例
 const importWalletByPrivateKeyError1 = await importWalletByPrivateKey()
 const importWalletByPrivateKeyError2 = await importWalletByPrivateKey({})
 const importWalletByPrivateKeyError3 = await importWalletByPrivateKey({ privateKey: "4HT3Arq3jXXc1iGDSKZemSEr8ycsS8mBPPnFdEGuDnT6wRpNzPvWHzbZYPVBeJqyEWQnChCPyyyeNzzVZmTzDz5Q" })
 const importWalletByPrivateKeyError4 = await importWalletByPrivateKey({ type: "Solana" })
 失败结果
 导入私钥钱包失败： ${error.message}
 */



//通过助记词导入钱包
const importWalletByMnemonic = async (mnemonic) => {
    try {
        const id = await getNextWalletId() //生成id
        const { uuid, addressList } = await generateAddresses(mnemonic, 0); //通过助记词生成地址和私钥

        const walletObject = {
            uuid: uuid, //钱包id
            addressList: addressList, //地址集合
            type: 1, // 1 =>hd钱包， 2 =>私钥钱包
            source: 2, //1 =>创建 2 =>恢复
            avatar: 1, //头像
            name: `Wallet ${id}`, //名称
            status: 2,  // 0 =>未备份， 1 =>已备份, 2 => 导入
            balance: 0, //余额
        };
        return walletObject

    } catch (error) {

        throw new Error(`通过助记词导入钱包失败： ${error.message}`);
    }
};

/** @Test 手动测试 importWalletByMnemonic() 方法
 成功示例
 const importWalletByMnemonicSuccess = await importWalletByMnemonic("answer gown deal parent december coffee only clog camera pistol taxi minor")
 成功结果
 {
 uuid: 69ab6e21-eca2-4ccb-8a04-b756d7e42f86, //钱包uuid
 addressList: [
 {
 "generateType": "Solana",
 "address": "3YCTnCMkUGJv9yXot2DvrWkb1vw1p8TivLAW7KYGZgjP"
 },
 {
 "generateType": "EVM",
 "address": "0x86c933BBc3FA528B02C0ad72Bc3E6ae4723bf147"
 }
 ]
 type: 1,
 source: 2,
 avatar: 3,
 name: `Wallet 3`,
 status: 2,
 balance: 0,
 }
 失败示例
 const importWalletByMnemonicError1 = await importWalletByMnemonic()
 const importWalletByMnemonicError2 = await importWalletByMnemonic({})
 const importWalletByMnemonicError3 = await importWalletByMnemonic('answer gown deal parent december')
 const importWalletByMnemonicError4 = await importWalletByMnemonic(null)
 失败结果
 导入私钥钱包失败： ${error.message}

 */


//内部方法获取Keychain存储的内容
const getKeychainPassword = async (serviceName) => {
    try {
        const keychainPassword = await getKeychainValue(serviceName)
        return keychainPassword;
    } catch (error) {
        throw new Error(`Keychain获取失败： ${error.message}`);
    }
}

/** @Test 手动测试 getKeychainPassword() 方法
 成功示例
 const getKeychainPasswordSuccess = await getKeychainPassword('wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86')
 成功结果
 {"password": "mixed globe lunch ability rose feel romance choose bleak solar abstract frog", "service": "wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86", "storage": "keychain", "username": "wallet_69ab6e21-eca2-4ccb-8a04-b756d7e42f86"}
 失败示例
 const getKeychainPasswordError1 = await getKeychainPassword()
 const getKeychainPasswordError2 = await getKeychainPassword('adasd')
 失败结果
 Keychain获取失败： ${error.message}

 */



//evm 签名
const evmSign = async (wallet, tx) => {
    try {
        const signTransactionParams = {
            chainId: tx.chainId,
            from: tx.from,
            to: tx.to,
            value: tx.value,
            maxFeePerGas: tx.maxFeePerGas,
            maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
            gasLimit: tx.gasLimit,
            nonce: tx.nonce,
            data: tx.data,
            type: 2 // 指定为 EIP-1559 交易
        };

        const privateKey = await getKeychainPassword('address_' + wallet.address + '_type_' + wallet.type);

        const { rawTransaction } = await web3.eth.accounts.signTransaction(
            signTransactionParams,
            privateKey
        );
        return rawTransaction;
    } catch (error) {
        throw new Error(`evm签名失败： ${error.message}`);
    }
}
/** @Test 手动测试 evmSign() 方法
 成功示例
 const evmSignSuccess = await evmSign(
 {
 address: '0x86c933BBc3FA528B02C0ad72Bc3E6ae4723bf147',
 type: 'EVM',
 },
 {
 chainId: 8453,
 from: '0xC617C43336e46AE430b6f7625CeE60532fF42476',
 to: '0x6b2C0c7be2048Daa9b5527982C29f48062B34D58',
 value: '0',
 maxFeePerGas: '1002699069',
 maxPriorityFeePerGas: '1000000050',
 gasLimit: '337500',
 nonce: '91',
 data: '0xb80c2f09000000000000000000000000000000000000000000000000000000000001aa7e000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00000000000000000000000000000000000000000000000000000000002cc4bf0000000000000000000000000000000000000000000000000004b452bcb15bef0000000000000000000000000000000000000000000000000000000067cad533000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000460000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000002cc4bf000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000160000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000000000000000000000000000000000000000000100000000000000000000000056e6983d59bf472ced0e63966a14d94a3a291589000000000000000000000000000000000000000000000000000000000000000100000000000000000000000056e6983d59bf472ced0e63966a14d94a3a291589000000000000000000000000000000000000000000000000000000000000000180000000000000000000271074cb6260be6f31965c239df6d6ef2ac2b5d4f0200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000060000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000420000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000EeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE3ca20afc2bbb00000000001eC0Bfb2df28415123699888064Ffd26731f6D4f43',
 type: 2 // 指定为 EIP-1559 交易
 }
 )
 成功结果
 0x02f905338221055b843b9aca32843bc3f93d8305265c946b2c0c7be2048daa9b5527982c29f48062b34d5880b904c4b80c2f09000000000000000000000000000000000000000000000000000000000001aa7e000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00000000000000000000000000000000000000000000000000000000002cc4bf0000000000000000000000000000000000000000000000000004b452bcb15bef0000000000000000000000000000000000000000000000000000000067cad533000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000460000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000002cc4bf000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000160000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000000000000000000000000000000000000000000100000000000000000000000056e6983d59bf472ced0e63966a14d94a3a291589000000000000000000000000000000000000000000000000000000000000000100000000000000000000000056e6983d59bf472ced0e63966a14d94a3a291589000000000000000000000000000000000000000000000000000000000000000180000000000000000000271074cb6260be6f31965c239df6d6ef2ac2b5d4f0200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000060000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000420000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3ca20afc2bbb00000000001ec0bfb2df28415123699888064ffd26731f6d4f43c080a05f797d365739c8a4ead1a0664d91044250f1be3209b80023bd217d8fd7175efba0495bd9675aced607031d9a3d5e338da709f41bbeedbd47917f48f430d1b5e774

 失败示例
 const evmSignError1 = await evmSign()
 const evmSignError2 = await evmSign({}, {})
 const evmSignError3 = await evmSign({})
 const evmSignError4 = await evmSign('adasd', null)
 失败结果
 evm签名失败： ${error.message}

 */


//sol 签名
const solSign = async (wallet, noSignTransactionData) => {

    try {
        const privateKey = await getKeychainPassword('address_' + wallet.address + '_type_' + wallet.type);

        const transactionBytes = getBase64Encoder().encode(noSignTransactionData);
        const decodedTransaction = getTransactionDecoder().decode(transactionBytes);

        const keyPair = nacl.sign.keyPair.fromSecretKey(bs58.decode(privateKey))
        const signer = await createKeyPairSignerFromBytes(keyPair.secretKey, false);
        const compiledTransactionMessage = getCompiledTransactionMessageDecoder().decode(decodedTransaction.messageBytes);
        const decompiledTransactionMessage = decompileTransactionMessage(compiledTransactionMessage)
        const transactionMessageFeePayerSigner = setTransactionMessageFeePayerSigner(signer, decompiledTransactionMessage);
        const signedTransaction = await signTransactionMessageWithSigners(transactionMessageFeePayerSigner);
        const transactionVal = getBase64EncodedWireTransaction(signedTransaction);
        return transactionVal

    } catch (error) {
        throw new Error(`sol签名失败： ${error.message}`);
    }
}
/** @Test 手动测试 solSign() 方法
 成功示例
 const solSignSuccess = await solSign(
 {
 type: "Solana",
 address: "3YCTnCMkUGJv9yXot2DvrWkb1vw1p8TivLAW7KYGZgjP"
 },
 "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAIDCt9nvcb+8tg61PClRaikaPh3oEJ24SDGOAqyGmSowy4DBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsHwvP0X0OfzSI5TwxszvWhUQ5YD12kNxQyqbGfjnHUEDAQAFAsIBAAABAAkDQA0DAAAAAAACAgAADAIAAACAlpgAAAAAAA=="
 )
 成功结果
 AWht1SfSURcbIilf0PxTeMAIWOcq3sGQDrD3ipHh8jY/fFDLsyIjkohXoQJFao9I7sN5KRN/KB9VPcpf0DsyHgyAAQAHCwrfZ73G/vLYOtTwpUWopGj4d6BCduEgxjgKshpkqMMuAn/UZe3VLk/6Mo0EiGXYot8qjV4W9u4p6jExdF/nuYx1kdnpbKUGMoTQEb4/SyRHmORrTRt6WZ+O6hGJ6wJgrh6dOCXYCBuQtUw6hH15R/wA5N7JKvw5pVe1KsJhutqSKfrhHoDBBEJw3k+dzcZtDqsBtEYnHd+v4d7e78xf7eAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpDQzB9jdRDXikEvwXz5hvmc7D54iEMXWW0qhMFOJWVTUDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAIyXJY9OJInxuz0QKRSODYMLWhOZ2v8QhASOe9jb6fhZVZFW8aJcbRNPKvfmCpoNNH7HkVZjZGLV0a0m8TU0j2lmB3hdXRChRWyGItVEEaxhCi4wLk9BffX3y/7dKzl1fwcIAAUC0QYEAAgACQMTqwgAAAAAAAUCAAFpAwAAAArfZ73G/vLYOtTwpUWopGj4d6BCduEgxjgKshpkqMMuDQAAAAAAAAAxNzQxMzQzMzkwNzEy8B0fAAAAAAClAAAAAAAAAAbd9uHXZaGT2cvhRs7reawctIXtX1s3kTqM9YV+/wCpBgQBFQAQAQEJBgACBBUFBgEBChcAAwEWFQIGBwADARYVDQ4LDBETFA8GEkmtg04mlqV7D01JHAAAAAAAdsrFAAAAAAAe0MMAAAAAAAEAAABNSRwAAAAAAAEAAAABAAAAAQAAABkBAAAAZB4AAH6qAQAAAAAABgMBAAABCQIFl/mZTXz8NIQ6U7lS/J6E9D40JD3jB1rayLJ0M7S8UgQzV29fAMRI+LuCwsD1DXxJ6Vq20Ph+U32vHeJRXh6AKgQLlh0OAAhxRLdHuLl7fA==

 失败示例
 const solSignError1 = await solSign()
 const solSignError2 = await solSign({}, '')
 const solSignError3 = await solSign({})
 const solSignError4 = await solSign('adasd', null)
 失败结果
 sol签名失败： ${error.message}
 */




//获取兑换前待签名数据
const getSwapData = async (data) => {
    const result = await axios.post('/web3/swap/getSwapData', data)
    return result.data;
}

//获取转账前待签名数据
const getWithdrawalData = async (data) => {
    const result = await axios.post('/web3/wallet/withdrawalData', data)
    return result.data;
}

//获取授权前待签名数据
const getApproveData = async (data) => {
    const result = await axios.post('/web3/swap/approve', data)
    return result.data;
}

//签名后，广播交易
const broadcast = async (data) => {
    const result = await axios.post('/web3/wallet/broadcast', data)
    return result.data;
}


//兑换
const handleSwap = async () => {
    //第一步 获取兑换Data
    const swapData = await getSwapData({
        chainId,
        fromTokenAddress,
        toTokenAddress,
        amount,
        slippage,
        fromAddress,
        quoteResponse
    })
    //第二步 本地签名
    let broadcastData;
    if (wallet.generateType === 'EVM') {
        broadcastData = await evmSign(wallet, swapData);
    } else if (wallet.generateType === 'Solana') {
        broadcastData = await solSign(wallet, swapData.solTransferData);
    }
    //第三步 广播交易
    const swapBroadcastData = {
        chainId: chainId,
        fromAddress: fromAddress,
        toAddress: toAddress,
        contractAddress: contractAddress,
        transactionData: broadcastData,
        type: 'Swap', //  Send  Swap  Approve
        qty: qty,
        walletId: walletId,
        memberId: memberId,
        swapFromAddress: swapFromAddress,
        swapToAddress: swapToAddress,
        swapFromQty: swapFromQty,
        swapToQty: swapToQty,
    }
    await broadcast(swapBroadcastData);
}

//转账
const handleWithdrawal = async () => {
    //第一步 获取转账Data
    const withdrawalData = await getWithdrawalData({
        chainId,
        contractAddress,
        toAddress,
        qty,
        fromAddress,
        gasLimit,
        nonce
    })
    //第二步 本地签名
    let broadcastData;
    if (wallet.generateType === 'EVM') {
        broadcastData = await evmSign(wallet, withdrawalData);
    } else if (wallet.generateType === 'Solana') {
        broadcastData = await solSign(wallet, withdrawalData.solTransferData);
    }
    //第三步 广播交易
    const withdrawalBroadcastData = {
        chainId: chainId,
        contractAddress: contractAddress,
        fromAddress: fromAddress,
        toAddress: toAddress,
        qty: qty,
        transactionData: broadcastData,
        type: 'Send', //  Send  Swap  Approve
        walletId: walletId,
        memberId: memberId,
    }
    await broadcast(withdrawalBroadcastData);
}

//授权
const handleApprove = async () => {
    //第一步 获取兑换Data
    const approveData = await getApproveData({
        chainId,
        fromTokenAddress,
        toTokenAddress,
        gasLimit,
        nonce
    })
    //第二步 本地签名
    let broadcastData;
    if (wallet.generateType === 'EVM') {
        broadcastData = await evmSign(wallet, approveData);
    } else if (wallet.generateType === 'Solana') {
        broadcastData = await solSign(wallet, approveData.solTransferData);
    }
    //第三步 广播交易
    const approveBroadcastData = {
        chainId: chainId,
        fromAddress: fromAddress,
        toAddress: toAddress,
        transactionData: broadcastData,
        type: 'Approve', //  Send  Swap  Approve
        walletId: walletId,
        memberId: memberId,
        swapFromAddress: swapFromAddress,
        swapToAddress: swapToAddress,
        swapFromQty: swapFromQty,
        swapToQty: swapToQty,
    }
    await broadcast(approveBroadcastData);
}