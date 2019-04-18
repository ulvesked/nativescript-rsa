import { stripPEMHeader, chunkSplit } from "./helper";

//// <reference path="../typings/CryptoExportImportManager.d.ts" />
//// <reference path="node_modules/tns-platform-declarations/android/android-platform-27.d.ts" />

const keystore: any = android.security['keystore'];
const Signature = java.security.Signature;

export enum RsaHashAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

function getProviderName(algo: RsaHashAlgorithm) {
    return RsaHashAlgorithm[algo] + "withRSA";
}

function stringToByteArray(data: string) {
    return (new java.lang.String(data)).getBytes();
}

export class Rsa {

    importPublicKey(tag: string, key: string) {
        let keyWithoutHeader = stripPEMHeader(key);
        let keyBytes = android.util.Base64.decode(keyWithoutHeader, android.util.Base64.DEFAULT);
        let spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        let kf = java.security.KeyFactory.getInstance("RSA");
        let pubKey = kf.generatePublic(spec);
        return new RsaKey(new java.security.KeyPair(pubKey, null));
    }
    loadKey(tag: string): RsaKey {
        const keyStore = java.security.KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        let entry = keyStore.getEntry(tag, null) as java.security.KeyStore.PrivateKeyEntry;
        let privKey = entry.getPrivateKey();
        let cert = entry.getCertificate();
        let pubKey = cert.getPublicKey();
        let keyPair = new java.security.KeyPair(pubKey, privKey);
        return new RsaKey(keyPair);
    }
    removeKeyFromKeychain(tag: string) {
        const keyStore = java.security.KeyStore.getInstance("AndroidKeyStore");
        keyStore.deleteEntry(tag);
    }
    generateKey(tag: string, keySize: number, permanent?: boolean): RsaKey {

        let keyGen: java.security.KeyPairGenerator;
        if (permanent) {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        }
        else {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA");
        }
        let params = new keystore.KeyGenParameterSpec.Builder(
            tag,
            keystore.KeyProperties.PURPOSE_SIGN | keystore.KeyProperties.PURPOSE_VERIFY,
        )
            .setDigests([keystore.KeyProperties.DIGEST_SHA256, keystore.KeyProperties.DIGEST_SHA512])
            .setSignaturePaddings([keystore.KeyProperties.SIGNATURE_PADDING_RSA_PKCS1])
            .setKeySize(keySize)
            .build();
        keyGen.initialize(params);
        let keyPair = keyGen.generateKeyPair();
        return new RsaKey(keyPair);

    }

    sign(data: string, key: RsaKey, alg: RsaHashAlgorithm): ArrayBuffer
    sign(data: string, key: RsaKey, alg: RsaHashAlgorithm, returnAsBase64: false): ArrayBuffer;
    sign(data: string, key: RsaKey, alg: RsaHashAlgorithm, returnAsBase64: true): string;
    sign(data: string, key: RsaKey, alg: RsaHashAlgorithm, returnAsBase64?: boolean): ArrayBuffer | string {
        const signEngine = Signature.getInstance(getProviderName(alg));
        let privateKey = key.valueOf().getPrivate();
        signEngine.initSign(privateKey);
        signEngine.update(stringToByteArray(data));
        let sign = signEngine.sign();
        if (returnAsBase64) {
            return android.util.Base64.encodeToString(sign, android.util.Base64.NO_WRAP);
        }
        else {
            return new Uint8Array(sign).buffer;
        }
    }
    verify(signature: string, data: string, key: RsaKey, alg: RsaHashAlgorithm): boolean {
        const signEngine = Signature.getInstance(getProviderName(alg));
        let publicKey = key.valueOf().getPublic()
        signEngine.initVerify(publicKey);
        signEngine.update(stringToByteArray(data));
        let signatureBytes = android.util.Base64.decode(signature, android.util.Base64.DEFAULT);
        return signEngine.verify(signatureBytes);
    }
}
export class RsaKey {
    private _keyPair: java.security.KeyPair;
    constructor(data: any) {
        this._keyPair = data;
    }
    valueOf(): any {
        return this._keyPair;
    }
    getPublicKey(): string {
        const kf = java.security.KeyFactory.getInstance("RSA");
        let pubSpec = kf.getKeySpec(this._keyPair.getPublic(), java.security.spec.X509EncodedKeySpec.class) as java.security.spec.X509EncodedKeySpec;
        let pubKeyB64 = android.util.Base64.encodeToString(pubSpec.getEncoded(), android.util.Base64.NO_WRAP);
        return "-----BEGIN PUBLIC KEY-----\r\n" + chunkSplit(pubKeyB64) + "\r\n-----END PUBLIC KEY-----";
    }
}