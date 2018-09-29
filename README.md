# Nativescript RSA

Simplifying RSA key generation, signing and verifying using native API:s.

## Installation

Install using nativescript-cli:

```javascript
tns plugin add nativescript-rsa
```

## Usage 
	
```js
import { Rsa, RsaHashAlgorithm } from 'nativescript-rsa';

var rsa = new Rsa();
var key = rsa.generateKey("org.nativescript.my-app.rsa-key", 2048);
var message = "Hello world";
var signature = rsa.sign(message, key, RsaHashAlgorithm.SHA256);
console.log('signature is ' + signature);
var isValid = rsa.verify(signature, message, key, RsaHashAlgorithm.SHA256);
console.log('signature is valid = ' + isValid);
```

## API

The API is relatively straight forward. The `Rsa` class is normally the only class you need to use directly.

### Class: Rsa

The main class for generating keys, signing and verifying. It contains the following methods:

#### importPublicKey

```js
importPublicKey(tag: string, key: string): RsaKey;
```
Imports a public key in PEM format into the keychain and returns a RsaKey instance.

| Argument | Type | Description |
| --- | --- | --- |
| tag | string | The tag or alias to associate with this key when storing in the keychain |
| key | string | PEM encoded public key in BASE64. May include the PEM headers (`-----BEGIN PUBLIC KEY-----`,  `-----END PUBLIC KEY-----`) |

#### loadKey

```js
loadKey(tag: string): RsaKey;
```
Loads the key with the specified tag from the keychain. Returns a RsaKey instance if found, null otherwise.

#### removeKeyFromKeychain

```js
removeKeyFromKeychain(tag: string): void;
```
Removes key with the specified tag from the keychain.

#### generateKey

```js
generateKey(tag: string, keySize: number, permanent?: boolean): RsaKey;
```
Generate a new Private/Public key pair with the specified key size. 

| Argument | Type | Description |
| --- | --- | --- |
| tag | string | The tag or alias to associate with this key when storing in the keychain |
| keySize | number | Key size in bits |
| permanent | boolean | (optional) Make this key persistent in the keychain. Non-Persistent keys remain available until you do not use them any more |

#### sign

```js
sign(data: string, key: RsaKey, alg: RsaHashAlgorithm): string;
```
Create a signature of specified data with a private key. Returns the signature as a Base64-string.

| Argument | Type | Description |
| --- | --- | --- |
| data | string | The data to be signed. Must be in UTF-8 encoding. |
| key | RsaKey | Private key to sign with. |
| alg | RsaHashAlgorithm | The algorithm to use. See RsaHashAlgorithm below for possible values |

#### verify

```js
verify(signature: string, data: string, key: RsaKey, alg: RsaHashAlgorithm): boolean;
```
Verifies a signature using a public key.

| Argument | Type | Description |
| --- | --- | --- |
| signature | string | The signature to verify. Must be a base64-string. |
| data | string | The data to be signed. Must be in UTF-8 encoding. |
| key | RsaKey | Public key to verify with. If a private key is specified, the public key will be extracted from it. |
| alg | RsaHashAlgorithm | The algorithm to use. See RsaHashAlgorithm below for possible values |

### Class: RsaKey
This class is a wrapper around the platform specific native keys.

Internally uses `SecKeyRef` for iOS and `java.security.KeyPair` for Android.

#### constructor

```js
constructor(data: SecKeyRef | java.security.KeyPair);
```
Create a RsaKey instance using a native key as data.

#### valueOf
```js
valueOf(): SecKeyRef | java.security.KeyPair;
```
Returns the native key that this RsaKey instance wraps.

#### getPublicKey
```js
getPublicKey(): string;
```
Returns the public key in PEM-format.

Example: 
```
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALj+sLdjL7fllvqQs+q4cgwtbAK2bgtx
pVRR/GQIpQSdqAFQnGVY5bVTMGozSNznQ+QhqvnZhUOO3G88SFJiSHUCAwEAAQ==
-----END PUBLIC KEY-----
```

### Enum: RsaHashAlgorithm

Has one of the following values:
```js
  SHA1
  SHA224
  SHA256
  SHA384
  SHA512
```
    
## License

The MIT License (MIT)
