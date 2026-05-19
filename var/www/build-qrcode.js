// build-qrcode.js
const fs = require("fs");
const path = require("path");
const browserify = require("browserify");
const terser = require("terser");

const outputDir = path.join(
  __dirname,
  "ufastauthd3",
  "global",
  "assets",
  "js"
);

const outputFile = path.join(outputDir, "qrcode.min.js");

async function buildQRCode() {
  fs.mkdirSync(outputDir, { recursive: true });

  const bundle = await new Promise((resolve, reject) => {
    browserify(require.resolve("qrcode"), {
      standalone: "QRCode"
    }).bundle((error, buffer) => {
      if (error) {
        reject(error);
        return;
      }

      resolve(buffer.toString());
    });
  });

  const minified = await terser.minify(bundle, {
    compress: true,
    mangle: true
  });

  if (minified.error) {
    throw minified.error;
  }

  fs.writeFileSync(outputFile, minified.code, "utf8");

  console.log("Generated:", outputFile);
}

buildQRCode().catch((error) => {
  console.error(error);
  process.exit(1);
});
