// 무해한 고정 파일 — esbuild·sharp 의 install.js 와 같은 모양 (설치 시점에 바이너리를 받는다).
// 규칙이 이것을 HIGH 로 내면 안 된다: 네트워크 호출만 있고 호스트 정보·비밀을 보내지 않는다.
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const platform = `${os.platform()}-${os.arch()}`;
const url = `https://registry.npmjs.org/@su-fixture/${platform}/-/${platform}-1.0.0.tgz`;
const dest = path.join(__dirname, "bin", "tool");

function download(u, out) {
  return new Promise((resolve, reject) => {
    https.get(u, (res) => {
      const file = fs.createWriteStream(out);
      res.pipe(file);
      file.on("finish", resolve);
    }).on("error", reject);
  });
}

download(url, dest).then(() => {
  // 받은 바이너리 버전 확인 — 환경변수를 자식 프로세스에 넘기는 것은 정상이다
  spawnSync(dest, ["--version"], { env: process.env, stdio: "inherit" });
});
