"use strict";

var assert = require("assert");
var xforgot = require("../xforgot");

describe("xforgot", function () {
  // 0 = default, 1 = with value
  // b = buffer, s = base58, otherwise bae64
  var salted0 = "wihGlqLO++MoiZh3OfbsP1BohqOOpjUlUU50HZlqba4=";
  var salted1 = "v4Hm1qhvxVE21UMqir3ZhiYAfimikWeAirYENIcbUEk=";
  var salted0b = new Buffer(salted0, "base64");
  var salted1b = new Buffer(salted1, "base64");
  var expect0 = "/dnEVzFm8AgFjH4OlF4JrLBkZCwrL2f7EZSLRF+1mWU=";
  var expect1 = "jgxCGs/hw1YTb/XiYqIj/TP1TcpJ7uB8KzvnDPkzywI=";
  var expect0s = "J5vk2Bzw4YBvJj6fF934aVoatu17wuzgtxmvjtP1Di28";
  var expect1s = "AZVjbEkjAMk3BfGbWqPgcLzUtitfJo9dN1moyvW2wDGD";
  var code0bs = "J5vk2Bzw4YBvJj6fF934aVoatu17wuzgtxmvjtP1Di28";
  var code1bs = "AZVjbEkjAMk3BfGbWqPgcLzUtitfJo9dN1moyvW2wDGD";

  describe("default export", function () {
    before(function () {
      this.x = xforgot;
    });

    it("should salt a secret with an empty salt", function () {
      var secret = this.x.digestSecret({secret: "xyzzy"});
      assert.equal(secret.toString("base64"), salted0);
    });

    it("should salt a secret with the given salt", function () {
      var secret = this.x.digestSecret({secret: "xyzzy", salt: "foobar"});
      assert.equal(secret.toString("base64"), salted1);
    });

    it("should digest with the default values", function () {
      var digest = this.x.digest({secret: "xyzzy", time: 0});
      assert.equal(digest.toString("base64"), expect0);
      digest = this.x.digest({salted: salted0b, time: 0});
      assert.equal(digest.toString("base64"), expect0);
    });

    it("should digest with the given salt", function () {
      var digest = this.x.digest({secret: "xyzzy", time: 0, salt: "foobar"});
      assert.equal(digest.toString("base64"), expect1);
      digest = this.x.digest({salted: salted1b, time: 0});
      assert.equal(digest.toString("base64"), expect1);
    });

    it("should digest with the given step", function () {
      var digest = this.x.digest({secret: "xyzzy", time: 0, step: 60*60});
      assert.equal(digest.toString("base64"), expect0);
      digest = this.x.digest({salted: salted0b, time: 0, step: 60*60});
      assert.equal(digest.toString("base64"), expect0);
    });

    it("should generate with the default values", function () {
      var code = this.x.generate({secret: "xyzzy", time: 0});
      assert.equal(code, expect0s);
      code = this.x.generate({salted: salted0b, time: 0});
      assert.equal(code, expect0s);
    });

    it("should generate with the given salt", function () {
      var code = this.x.generate({secret: "xyzzy", time: 0, salt: "foobar"});
      assert.equal(code, expect1s);
      code = this.x.generate({salted: salted1b, time: 0});
      assert.equal(code, expect1s);
    });

    it("should generate with the given step", function () {
      var code = this.x.generate({secret: "xyzzy", time: 0, step: 60*60});
      assert.equal(code, expect0s);
      code = this.x.generate({salted: salted0b, time: 0, step: 60*60});
      assert.equal(code, expect0s);
    });

    it("should verify with the default values", function () {
      assert(this.x.verify({token: code0bs, secret: "xyzzy", time: 0}));
      assert(this.x.verify({token: code0bs, salted: salted0b, time: 0}));
      assert(!this.x.verify({token: "code", salted: salted0b, time: 0}))
    });

    it("should verify with the given salt", function () {
      assert(this.x.verify({token: code1bs, secret: "xyzzy", time: 0, salt: "foobar"}));
      assert(this.x.verify({token: code1bs, salted: salted1b, time: 0}));
      assert(!this.x.verify({token: "code", salted: salted1b, time: 0}))
    });

    it("should verify with the given step", function () {
      assert(this.x.verify({token: code0bs, secret: "xyzzy", time: 0, step: 60*60}));
      assert(this.x.verify({token: code0bs, salted: salted0b, time: 0, step: 60*60}));
      assert(!this.x.verify({token: "code", salted: salted0b, time: 0, step: 60*60}));
    });
  });

  describe("XForgot with default options", function () {
    before(function () {
      this.x = new xforgot.XForgot();
    });

    it("should salt a secret with an empty salt", function () {
      var secret = this.x.digestSecret({secret: "xyzzy"});
      assert.equal(secret.toString("base64"), salted0);
    });

    it("should digest with the default values", function () {
      var digest = this.x.digest({secret: "xyzzy", time: 0});
      assert.equal(digest.toString("base64"), expect0);
      digest = this.x.digest({salted: salted0b, time: 0});
      assert.equal(digest.toString("base64"), expect0);
    });

    it("should generate with the default values", function () {
      var code = this.x.generate({secret: "xyzzy", time: 0});
      assert.equal(code, expect0s);
      code = this.x.generate({salted: salted0b, time: 0});
      assert.equal(code, expect0s);
    });

    it("should verify with the default values", function () {
      assert(this.x.verify({token: code0bs, secret: "xyzzy", time: 0}));
      assert(this.x.verify({token: code0bs, salted: salted0b, time: 0}));
      assert(!this.x.verify({token: "code", salted: salted0b, time: 0}))
    });
  });

  describe("XForgot with salt", function () {
    before(function () {
      this.x = new xforgot.XForgot({salt: "foobar"});
    });

    it("should salt a secret with the given salt", function () {
      var secret = this.x.digestSecret({secret: "xyzzy"});
      assert.equal(secret.toString("base64"), salted1);
    });

    it("should digest with the given salt", function () {
      var digest = this.x.digest({secret: "xyzzy", time: 0});
      assert.equal(digest.toString("base64"), expect1);
      digest = this.x.digest({salted: salted1b, time: 0});
      assert.equal(digest.toString("base64"), expect1);
    });

    it("should generate with the given salt", function () {
      var code = this.x.generate({secret: "xyzzy", time: 0});
      assert.equal(code, expect1s);
      code = this.x.generate({salted: salted1b, time: 0});
      assert.equal(code, expect1s);
    });

    it("should verify with the given salt", function () {
      assert(this.x.verify({token: code1bs, secret: "xyzzy", time: 0}));
      assert(this.x.verify({token: code1bs, salted: salted1b, time: 0}));
      assert(!this.x.verify({token: "code", salted: salted1b, time: 0}))
    });
  });

  describe("XForgot with step", function () {
    before(function () {
      this.x = new xforgot.XForgot({step: 60*60});
    });

    it("should digest with the given step", function () {
      var digest = this.x.digest({secret: "xyzzy", time: 0});
      assert.equal(digest.toString("base64"), expect0);
      digest = this.x.digest({salted: salted0b, time: 0});
      assert.equal(digest.toString("base64"), expect0);
    });

    it("should generate with the given step", function () {
      var code = this.x.generate({secret: "xyzzy", time: 0});
      assert.equal(code, expect0s);
      code = this.x.generate({salted: salted0b, time: 0});
      assert.equal(code, expect0s);
    });

    it("should verify with the given step", function () {
      assert(this.x.verify({token: code0bs, secret: "xyzzy", time: 0}));
      assert(this.x.verify({token: code0bs, salted: salted0b, time: 0}));
      assert(!this.x.verify({token: "code", salted: salted0b, time: 0}));
    });
  });

});
