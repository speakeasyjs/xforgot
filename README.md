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

if (xforgot.verify({ token: token, secret: "xyzzy", salt: "foobar" })) {
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

Note the `secret` option is required to both generate and verify user-specific
tokens. Otherwise, everyone would be able to reset each other's passwords 😱

On the other hand, the `salt` option is used to make it more difficult for
someone to generate valid tokens if a hacker were to somehow gain access to the
user-specific secret. The salt may be generated per token or set per
application. In either case, the salt should be stored separately from the user-
specific secret for better security.

## Documentation

Full documentation at http://mikepb.github.io/xforgot/

## License

MIT
