import { Observable } from 'tns-core-modules/data/observable';
import { Rsa } from 'nativescript-rsa';

export class HelloWorldModel extends Observable {
  public message: string;
  private rsa: Rsa;

  constructor() {
    super();

    this.rsa = new Rsa();
    this.message = this.rsa.message;
  }
}
