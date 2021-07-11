import { getViewById, Observable } from '@nativescript/core'
import { Rsa, RsaKey, RsaHashAlgorithm } from 'nativescript-rsa';

export class HelloWorldModel extends Observable {
  public message: string;
  private rsa: Rsa;
  private key: RsaKey;
  private signature: string;
  private tag = "com.kustevent.rsa.demo.key.testtag";

  constructor() {
    super();

    this.rsa = new Rsa();
    this.message = "Hello world";
  }

  loadKey(args) {
    console.log('loadKey');
    this.key = this.rsa.loadKey(this.tag);
  }

  test() {
    let tag = 'com.kustevent.rsa.demo.key.test'
    let key = this.rsa.generateKey(tag, 1024, true);
    console.log(key);
    let loadedKey = this.rsa.loadKey(tag);
    console.log(loadedKey);
  }

  getPublicKey(args) {
    console.log('tap');
    this.key = this.rsa.generateKey(this.tag, 512, true);
    //  this.test(this.key);
    let pub = this.key.getPublicKey();
    console.log(pub);
    let pubkeyField: any = getViewById(args.object.page, "pubkey");
    pubkeyField.text = pub;
  }
  sign(args) {
    let msgField: any = getViewById(args.object.page, "msg");
    this.signature = this.rsa.sign(msgField.text, this.key, RsaHashAlgorithm.SHA256, true);
    console.log(this.signature);

    let signField: any = getViewById(args.object.page, "sig");
    signField.text = this.signature;
  }
  verify(args) {
    let msgField: any = getViewById(args.object.page, "msg");
    let sigField: any = getViewById(args.object.page, "sig");
    let pubkeyField: any = getViewById(args.object.page, "pubkey");
    let key;
    if (pubkeyField.text.length == 0) {
      if (this.key) {
        console.log('use preloaded key')
        key = this.key;
      }
      else {
        console.log('load key from tag')
        key = this.rsa.loadKey(this.tag);
      }
    }
    else {
        console.log('import public key')
        key = this.rsa.importPublicKey(`${this.tag}.pubkey`, pubkeyField.text);
    }
//    key = this.key;
    let result = this.rsa.verify(sigField.text, msgField.text, key, RsaHashAlgorithm.SHA256);
    console.log(result);
    alert(result);
  }
}
