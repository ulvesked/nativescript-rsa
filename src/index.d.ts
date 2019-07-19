export declare enum RsaHashAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}
export declare class Rsa {
  importPublicKey(tag: string, key: string): RsaKey;
  importPrivateKey(tag: string, key: string): RsaKey;
  removeKeyFromKeychain(tag: string): void;
  loadKey(tag: string): RsaKey | null;
  generateKey(tag: string, keySize: number, permanent?: boolean): RsaKey;
  sign(data: string, key: RsaKey, alg: RsaHashAlgorithm): ArrayBuffer
  sign(data: string, key: RsaKey, alg: RsaHashAlgorithm, returnAsBase64: false): ArrayBuffer;
  sign(data: string, key: RsaKey, alg: RsaHashAlgorithm, returnAsBase64: true): string;
  verify(signature: string | ArrayBuffer, data: string, key: RsaKey, alg: RsaHashAlgorithm): boolean;
}
export declare class RsaKey {
  constructor(data: any);
  valueOf(): any;
  getPublicKey(): string;
}
