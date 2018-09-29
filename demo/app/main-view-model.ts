import { Observable } from 'tns-core-modules/data/observable';
import { Rsa, RsaKey, RsaHashAlgorithm } from 'nativescript-rsa';
import { getViewById } from 'tns-core-modules/ui/page/page';

export class HelloWorldModel extends Observable {
  public message: string;
  private rsa: Rsa;
  private key: RsaKey;
  private signature: string;
  private tag = "com.kustevent.app.test";


  constructor() {
    super();

    this.rsa = new Rsa();
    this.message = "Hello world";
  }
  getPublicKey(args) {
    console.log('tap');
    this.key = this.rsa.generateKey(this.tag, 512);
    let pub = this.key.getPublicKey();
    console.log(pub);
    let pubkeyField: any = getViewById(args.object.page, "pubkey");
    pubkeyField.text = pub;
  }
  sign(args) {
    let msgField: any = getViewById(args.object.page, "msg");
    this.signature = this.rsa.sign(msgField.text, this.key, RsaHashAlgorithm.SHA256);
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
      key = this.key;
    }
    else {
      key = this.rsa.importPublicKey(this.tag, pubkeyField.text);
    }
    let result = this.rsa.verify(sigField.text, msgField.text, key, RsaHashAlgorithm.SHA256);
    console.log(result);
    alert(result);
  }
}
