import * as asn from 'asn1js';
import { decodeToArrayBuffer, encode } from 'nativescript-base64';

const oid_rsaEncryption = "1.2.840.113549.1.1.1";
import { stripPEMHeader } from "./helper";

export function decodePEM(pem: string): ArrayBuffer {
    const base64 = stripPEMHeader(pem);
    return decodeToArrayBuffer(base64);
}
export function encodePEM(buffer: ArrayBuffer, label?: string): string {
    const includeLabel = typeof label == "string" && label.length > 0;
    const base64 = encode(buffer, { lineLength: 64, lineFeedCR: true, lineFeedLF: true });
    const a = new Array<string>();
    if (includeLabel) {
        a.push(`-----BEGIN ${label}-----`);
    }
    a.push(base64);
    if (includeLabel) {
        a.push(`-----END ${label}-----`);
    }
    return a.join("\r\n");
}

export function test(rawPublicKey: ArrayBuffer) {
    const a = new Uint8Array(rawPublicKey);
    let s = "";
    for (let i = 0; i < a.byteLength && i < 10; i++) {
        let n = a[i];
        s += n.toString(16) + ' ';
    }
    console.log(s);
    const data = asn.fromBER(rawPublicKey);
    console.log(data.offset);
    console.log(data.result);

}
export function exportPublicKeyToPEM(rawKeyData: ArrayBuffer) {
    let header = new asn.Sequence({
        value: [
            new asn.ObjectIdentifier({ value: oid_rsaEncryption }),
            new asn.Null()
        ]
    });
    let body = new asn.BitString({
        valueHex: rawKeyData
    });
    let result = new asn.Sequence({
        value: [
            header,
            body
        ]
    });
    console.log(encode(rawKeyData));
    return encodePEM(result.toBER(), "PUBLIC KEY");
}


export function getRawKeyFromPEM(key: string) {
    let data = decodePEM(key);
    return getRawKey(data);
}

export function getRawKey(keyData: ArrayBuffer) {
    const key = asn.fromBER(keyData);
    if (key.offset == -1) {
        console.log(key.result.error);
        return null;
    }
    if (!(key.result instanceof asn.Sequence)) {
        console.log('not a sequence');
        return null;
    }
    if (key.result.valueBlock.value.length == 2
        && key.result.valueBlock.value[0] instanceof asn.Integer
        && key.result.valueBlock.value[1] instanceof asn.Integer) {
        // Key is raw DER public key
        return keyData;
    }
    else if (key.result.valueBlock.value.length == 2
        && key.result.valueBlock.value[0] instanceof asn.Sequence
        && key.result.valueBlock.value[1] instanceof asn.BitString) {
        // Check OID header
        const header = key.result.valueBlock.value[0] as asn.Sequence;
        const bitString = key.result.valueBlock.value[1] as asn.BitString;
        let oid: string;
        if (header.valueBlock.value.length > 0 && header.valueBlock.value[0] instanceof asn.ObjectIdentifier) {
            oid = (header.valueBlock.value[0] as asn.ObjectIdentifier).valueBlock.toString();
            console.log(`found OID ${oid}`);
        }
        else {
            console.log('no oid found');
            return null;
        }
        return bitString.valueBlock.valueHex;
    }
    else {
        console.log('not valid public key');
        return null;
    }
}


// const publicKeyBase64 = `MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJrbqobU0/tyyAbPfhCjmjA3tSkuEpJR
// 4CK/8NdYWqgQTR+BzFuJF0DzAITOWZSYX8AEw2KhmAVNErfiy1/S9EECAwEAAQ==`;
// // MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJrbqobU0/tyyAbPfhCjmjA3tSkuEpJR4CK/8NdYWqgQTR+BzFuJF0DzAITOWZSYX8AEw2KhmAVNErfiy1/S9EECAwEAAQ==
// // MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJrbqobU0/tyyAbPfhCjmjA3tSkuEpJR4CK/8NdYWqgQTR+BzFuJF0DzAITOWZSYX8AEw2KhmAVNErfiy1/S9EECAwEAAQ==

// const rawKeyBase64 = `MEgCQQCa26qG1NP7csgGz34Qo5owN7UpLhKSUeAiv/DXWFqoEE0fgcxbiRdA8wCEzlmUmF/ABMNioZgFTRK34stf0vRBAgMBAAE=`;

// const key = decodeBase64(publicKeyBase64);
// const rawKey = decodeBase64(rawKeyBase64);

// const pem = exportPublicKeyToPEM(rawKey);
// console.log(pem);
// const raw = getRawKey(key);