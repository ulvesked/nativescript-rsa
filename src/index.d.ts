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
  loadKey(tag: string): RsaKey;
  generateKey(tag: string, keySize: number, permanent?: boolean): RsaKey;
  sign(data: string, key: RsaKey, alg: RsaHashAlgorithm): string;
  verify(signature: string, data: string, key: RsaKey, alg: RsaHashAlgorithm): boolean;
}
export declare class RsaKey {
  constructor(data: any);
  valueOf(): any;
  getPublicKey(): string;
}
