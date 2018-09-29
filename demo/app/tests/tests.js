var Rsa = require("nativescript-rsa").Rsa;
var rsa = new Rsa();

describe("greet function", function() {
    it("exists", function() {
        expect(rsa.greet).toBeDefined();
    });

    it("returns a string", function() {
        expect(rsa.greet()).toEqual("Hello, NS");
    });
});