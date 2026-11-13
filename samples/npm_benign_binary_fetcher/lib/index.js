"use strict";
const path = require("path");
// require 시점에는 경로만 계산한다 — 네트워크는 함수를 부를 때만
module.exports.binaryPath = () => path.join(__dirname, "..", "bin", "tool");
module.exports.check = function check() {
  return fetch("https://registry.npmjs.org/su-fixture-binary-fetcher");
};
