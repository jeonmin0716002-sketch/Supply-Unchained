"use strict";
// node-gyp-build 가 빌드된 .node 파일을 찾아 불러온다 — 흔한 네이티브 애드온 진입점
module.exports = require("node-gyp-build")(__dirname);
