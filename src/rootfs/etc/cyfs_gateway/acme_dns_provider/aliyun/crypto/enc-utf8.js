;(function (root, factory) {
	if (typeof exports === "object") {
		// CommonJS
		let core = require("./core");
		module.exports = exports = factory(core);
	}
	else if (typeof define === "function" && define.amd) {
		// AMD
		define(["./core"], factory);
	}
	else {
		// Global (browser)
		factory(root.CryptoJS);
	}
}(this, function (CryptoJS) {

	return CryptoJS.enc.Utf8;

}));
