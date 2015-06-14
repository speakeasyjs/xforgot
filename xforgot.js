"use strict";

/*
 * Module dependencies.
 */

var bs58 = require("bs58");
var crypto = require("crypto");
var passcode = require("passcode");

/**
 * Default salt value.
 */

const DEFAULT_SALT = "";

/**
 * Default time step value.
 */

const DEFAULT_STEP = 24*60*60;

/**
 * Default window value.
 */

const DEFAULT_WINDOW = 1;

/**
 * Copy properties from sources to target.
 *
 * @param {Object} target The target object.
 * @param {...Object} sources The source object.
 * @return {Object} The target object.
 * @private
 */

var extend = function (target /* ...sources */) {
  var source, key, i = 1;
  while (source = arguments[i++]) {
    for (key in source) target[key] = source[key];
  }
  return target;
};

/**
 * Create a new XForgot instance.
 *
 *
 * The XForgot class overrides the default options used when generating and
 * verifying time-limited one-time passwords. The default XForgot instance
 * on the `xforgot` export is configured with an empty salt, a time step of
 * 24 hours, and a window of 1 day.
 *
 * Setting a unique salt for your application allows you to more securely
 * derive password reset tokens from, for example, the cryptographic hash of
 * the password stored in a database. In the event that a hacker gains
 * access to your database, the salt helps to thward the hacker from
 * generating valid password reset tokens. Instead, the hacker must also
 * gain access to the salt value, which should be stored separately and
 * securely from your database. Using a Trusted Platform Module (TPM) or
 * similarly secure system for storing the salt may provide additional
 * security.
 *
 * The default time step of 24 hours with a window of 1 day gives users at
 * least 24 hours to use the token to reset their password. With these
 * settings, the generated tokens expire after at most 48 hours. You may
 * need to adjust these settings if you have more stringent security
 * or usability requirements.
 *
 * @param {Object} options
 * @param {String} [options.salt=""] A salt for deriving the secret key used
 *   for generating the one-time password.
 * @param {Integer} [options.step=24*60*60] Time step in seconds.
 * @param {Integer} [options.window=1] The allowable margin for the counter.
 *   The function will check "W" codes in the future and the past against the
 *   provided passcode, e.g. if W = 5, and C = 1000, this function will check
 *   the passcode against all One Time Passcodes between 995 and 1005,
 *   inclusive.
 * @constructor
 */

function XForgot (options) {
  extend(this, options);
};

/**
 * Digest the given secret key with the configured salt.
 *
 * @param {Object} options
 * @param {String} options.secret A user-specific secret, e.g. the password.
 * @param {String} [options.salt=this.salt||""] A salt for deriving the
 *   secret key used for generating the one-time password.
 * @return {Buffer} The salted and digested secret.
 * @memberof XForgot
 */

XForgot.prototype.digestSecret = function digestSecret (options) {

  // unpack options
  if (!options) options = {};
  var secret = options.secret;
  var salt = options.salt || this.salt || DEFAULT_SALT;

  // hash secret with salt
  var hmac = crypto.createHmac("sha256", salt);
  hmac.write(secret);

  // return buffer
  return hmac.digest();
};

/**
 * Generate a time-based one-time password as a Buffer.
 *
 * @param {Object} options
 * @param {String} options.secret A user-specific secret, e.g. the password.
 * @param {String} [options.salt=this.salt||""] A salt for deriving the
 *   secret key used for generating the one-time password.
 * @param {Integer} [options.step=24*60*60] Time step in seconds.
 * @param {Integer} [options.time] Time with which to calculate counter value.
 * @param {Integer} [options.counter] Counter value, calculated by default.
 * @return {Buffer} The one-time password.
 * @memberof XForgot
 */

XForgot.prototype.digest = function digest (options) {

  // unpack options
  if (!options) options = {};
  var secret = options.salted || this.digestSecret(options);
  var step = options.step || this.step || DEFAULT_STEP;
  var time = options.time;

  // calculate totp counter value
  var counter = options.counter;
  if (counter == null) counter = passcode._counter({step: step, time: time});

  // generate totp value
  return passcode.digest({
    secret: secret,
    counter: counter,
    algorithm: "sha256"
  });
};

/**
 * Generate an URL-safe time-based one-time password.
 *
 * @param {Object} options
 * @param {String} options.secret A user-specific secret, e.g. the password.
 * @param {String} [options.salt=this.salt||""] A salt for deriving the
 *   secret key used for generating the one-time password.
 * @param {Integer} [options.step=24*60*60] Time step in seconds.
 * @param {Integer} [options.time] Time with which to calculate counter value.
 * @param {Integer} [options.counter] Counter value, calculated by default.
 * @return {String} The one-time password encoded using base58.
 * @memberof XForgot
 */

XForgot.prototype.generate = function generate (options) {
  return bs58.encode(this.digest(options));
};

/**
 * Verify a time-based one-time password.
 *
 * @param {Object} options
 * @param {String} options.secret A user-specific secret, e.g. the password.
 * @param {String} options.token One-time password to verify.
 * @param {String} [options.salt=this.salt||""] A salt for deriving the
 *   secret key used for generating the one-time password.
 * @param {Integer} [options.step=24*60*60] Time step in seconds.
 * @param {Integer} [options.time] Time with which to calculate counter value.
 * @param {Integer} [options.counter] Counter value, calculated by default.
 * @param {Integer} [options.window=1] The allowable margin for the counter.
 *   The function will check "W" codes in the future and the past against the
 *   provided passcode, e.g. if W = 5, and C = 1000, this function will check
 *   the passcode against all One Time Passcodes between 995 and 1005,
 *   inclusive.
 * @return {Boolean} True if the one-time password is valid, false otherwise.
 * @memberof XForgot
 */

XForgot.prototype.verify = function verify (options) {
  var i;

  // shadow options
  options = Object.create(options);

  // unpack options
  if (!options) options = {};
  var token = options.token;
  var secret = options.salted || this.digestSecret(options);
  var step = options.step || this.step || DEFAULT_STEP;
  var time = options.time;
  var window = options.window || this.window || DEFAULT_WINDOW;

  // calculate totp counter value
  var counter = options.counter;
  if (counter == null) counter = passcode._counter({step: step, time: time});

  // loop from C to C + W
  for (i = counter - window; i <= counter + window; ++i) {
    options.counter = i;
    if (token == this.generate(options)) {
      // found a matching code, return delta
      return true;
    }
  }

  // no codes have matched
  return false;
};

/*
 * Configure default instance and export.
 */

var singleton = new XForgot();

// bind methods
Object.keys(XForgot.prototype).forEach(function (method) {
  singleton[method] = singleton[method].bind(singleton);
});

// export default generate
exports = module.exports = singleton.generate;

// assign methods
Object.keys(XForgot.prototype).forEach(function (method) {
  exports[method] = singleton[method];
});

/*
 * Export XForgot class.
 */

exports.XForgot = XForgot;

/**
 * @borrows XForgot#digestSecret as digestSecret
 * @namespace xforgot
 */

/**
 * @borrows XForgot#digest as digest
 * @namespace xforgot
 */

/**
 * @borrows XForgot#generate as generate
 * @namespace xforgot
 */

/**
 * @borrows XForgot#verify as verify
 * @namespace xforgot
 */
