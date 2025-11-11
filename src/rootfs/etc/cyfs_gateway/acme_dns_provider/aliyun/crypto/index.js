;(function (root, factory, undef) {
	let core = require("./core");
	let crypto_js = require("./crypto-js");
	let base64 = require("./enc-base64");
	let latin1 = require("./enc-latin1");
	let utf8 = require("./enc-utf8");
	let hmac = require("./hmac");
	let sha1 = require("./sha1");
	let hmac_sha1 = require("./hmac-sha1");
	module.exports = factory(core, crypto_js, latin1, utf8, hmac, sha1, hmac_sha1, base64);
}(this, function (CryptoJS) {

	return CryptoJS;

}));
