/// <reference path="./RSAKeyUtils.d.ts" />

import { stripPEMHeader } from "./helper";

export enum RsaHashAlgorithm {
    SHA1 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1,
    SHA224 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224,
    SHA256 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256,
    SHA384 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384,
    SHA512 = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512
}
export enum RsaEncryptionAlgorithm {
    RAW = kSecKeyAlgorithmRSAEncryptionRaw,
    PKCS1 = kSecKeyAlgorithmRSAEncryptionPKCS1,
    // RSA Encryption OAEP
    OAEP_SHA1 = kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
    OAEP_SHA224 = kSecKeyAlgorithmRSAEncryptionOAEPSHA224,
    OAEP_SHA256 = kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
    OAEP_SHA384 = kSecKeyAlgorithmRSAEncryptionOAEPSHA384,
    OAEP_SHA512 = kSecKeyAlgorithmRSAEncryptionOAEPSHA512,
    //RSA Encryption OAEP AESGCM
    OAEP_SHA1_AESGCM = kSecKeyAlgorithmRSAEncryptionOAEPSHA1AESGCM,
    OAEP_SHA224_AESGCM = kSecKeyAlgorithmRSAEncryptionOAEPSHA224AESGCM,
    OAEP_SHA256_AESGCM = kSecKeyAlgorithmRSAEncryptionOAEPSHA256AESGCM,
    OAEP_SHA384_AESGCM = kSecKeyAlgorithmRSAEncryptionOAEPSHA384AESGCM,
    OAEP_SHA512_AESGCM = kSecKeyAlgorithmRSAEncryptionOAEPSHA512AESGCM

}

function stringToNSData(data: string) {
    return NSString.stringWithString(data).dataUsingEncoding(NSUTF8StringEncoding);
}

export class Rsa {

    importPublicKey(tag: string, key: string) {
        let pubKey = RSAKeyUtils.importPublicKeyFromPEMTagName(stripPEMHeader(key), tag);
        return new RsaKey(pubKey);
    }
    importPrivateKey(tag: string, key: string) {
        let privKey = RSAKeyUtils.importPrivateKeyFromPEMTagName(stripPEMHeader(key), tag);
        return new RsaKey(privKey);
    }
    removeKeyFromKeychain(tag: string) {
        RSAKeyUtils.removeKeyFromKeychain(tag);
    }
    loadKey(tag: string): RsaKey {

        const privTagData = stringToNSData(tag);
        const query = NSMutableDictionary.new();
        query.setValueForKey(kSecClassKey, kSecClass);
        query.setValueForKey(privTagData, kSecAttrApplicationTag);
        query.setValueForKey(kSecAttrKeyTypeRSA, kSecAttrKeyType);
        query.setValueForKey(true, kSecReturnRef);
        const keyRef = new interop.Reference<any>();
        let status = SecItemCopyMatching(query, keyRef);
        //  CFRelease(query);
        if (status != errSecSuccess) {
            console.log('error: ' + status);
            throw new Error(`loadKey failed with status ${status}`);
        }
        else {
            return new RsaKey(keyRef);
        }

    }
    generateKey(tag: string, keySize: number, permanent?: boolean) {

        const privTagData = stringToNSData(tag);
        const params = NSMutableDictionary.new();
        params.setValueForKey(kSecAttrKeyTypeRSA, kSecAttrKeyType);
        params.setValueForKey(NSNumber.numberWithInt(keySize), kSecAttrKeySizeInBits);
        const privAttrs = NSMutableDictionary.new();

        if (permanent) {
            privAttrs.setValueForKey(kCFBooleanTrue, kSecAttrIsPermanent);
        }

        privAttrs.setValueForKey(privTagData, kSecAttrApplicationTag);
        params.setObjectForKey(privAttrs, kSecPrivateKeyAttrs);

        const err = new interop.Reference<NSError>();
        const keyPair = SecKeyCreateRandomKey(params, err);
        if (keyPair === null) {
            console.log("No key returned: ", err.value);
            throw err;
        } else {
            console.log("Key returned: ", keyPair);
            let result = new RsaKey(keyPair);
            return result;
        }


    }

    sign(data: string, key: RsaKey, alg: RsaHashAlgorithm) {
        //let err = new interop.Reference<NSError>();
        let nsData = stringToNSData(data);
        let signature = SecKeyCreateSignature(key.valueOf(), alg, nsData, undefined);
        let result = signature.base64EncodedStringWithOptions(0);
        // if (nsData) {
        //     CFRelease(nsData);
        // }
        // if (signature) {
        //     CFRelease(signature);
        // }
        // if (err && err.value) {
        //     CFRelease(err);
        // }
        return result;
    }
    verify(signature: string, data: string, key: RsaKey, alg: RsaHashAlgorithm) {
        //    let err = new interop.Reference<NSError>();
        console.log(signature, data, key, alg);
        let signatureBytes = NSData.alloc().initWithBase64Encoding(signature);
        let nsData = stringToNSData(data);
        let result = SecKeyVerifySignature(key.valueOf(), alg, nsData, signatureBytes, undefined);
        // if (nsData) {
        //     CFRelease(nsData);
        // }
        // if (signatureBytes) {
        //     CFRelease(signatureBytes);
        // }
        // if (err && err.value) {
        //     CFRelease(err);
        // }
        return result;
    }
    // encrypt(data: string, key: RsaKey, alg: RsaEncryptionAlgorithm) {
    //     let rawData = stringToNSData(data);
    //     const err = new interop.Reference<NSError>();
    //     let encryptedData = SecKeyCreateEncryptedData(key.valueOf(), alg, rawData, err);
    //     return encryptedData;
    // }
    // decrypt(encryptedData: string, key: RsaKey, alg: RsaEncryptionAlgorithm) {
    //     let encryptedDataBytes = stringToNSData(encryptedData);
    //     const err = new interop.Reference<NSError>();
    //     let plaintextData = SecKeyCreateEncryptedData(key.valueOf(), alg, encryptedDataBytes, err);
    //     return plaintextData;
    // }

}

export class RsaKey {
    private _secKeyRef: any;
    constructor(data: any) {
        this._secKeyRef = data;
    }
    valueOf(): any {
        return this._secKeyRef;
    }
    getPublicKey(): string {
        let pubKeyRef: any, err: interop.Reference<NSError>, pubKeyData: NSData;

        try {
            pubKeyRef = SecKeyCopyPublicKey(this._secKeyRef);
            console.log(pubKeyRef);
            err = new interop.Reference<NSError>();
           // pubKeyData = SecKeyCopyExternalRepresentation(this._secKeyRef, err);
          //  console.log(pubKeyData);
            if (err && err.value) {
                console.log("ERR", err.value.localizedDescription);
                throw err.value.localizedDescription;
            }
            return RSAKeyUtils.exportPublicKeyToPEM(pubKeyRef);
        }
        finally {
            // if (pubKeyData) {
            //     CFRelease(pubKeyData);
            // }
            // if (pubKeyRef) {
            //     CFRelease(pubKeyRef);
            // }
            // if (err) {
            //     CFRelease(err);
            // }
        }
    }
}