# `xforgot` - a library for generating password reset tokens

`xforgot` generates and verifies time-limited one time passwords suitable for
including in password reset links.

## Install

```sh
npm install --save xforgot
```

## Usage

```js
var xforgot = require("xforgot");
var token = xforgot({secret: "xyzzy", salt: "foobar"});

// Send token to user via URL...

if (xforgot.verify(token)) {
  // Reset the user's password...
}
```

Alternatively, you may create an instance of XForgot to override the default
settings:

```js
var XForgot = require("xforgot").XForgot;
var xforgot = new XForgot({salt: "xyzzy"});
// Continue as before...
```

## Documentation

Full documentation at http://mikepb.github.io/xforgot/

## License

MIT
