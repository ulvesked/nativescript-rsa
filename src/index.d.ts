export declare enum RsaHashAlgorithm {
  SHA1 = 0,
  SHA224 = 1,
  SHA256 = 2,
  SHA384 = 3,
  SHA512 = 4,
}
export declare class Rsa {
  importPublicKey(tag: string, key: string): RsaKey;
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
