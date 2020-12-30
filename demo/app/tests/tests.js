var Rsa = require("nativescript-rsa").Rsa;
var rsa = new Rsa();
var keyTag = 'org.nativescript.rsa.test';

describe("RSA key generation, signing and ", function() {
    it("should generate a new key pair", function() {
        rsa.generateKey()
        expect(rsa.greet).toBeDefined();
    });

    it("returns a string", function() {
        expect(rsa.greet()).toEqual("Hello, NS");
    });
});