const { getDefaultConfig } = require("expo/metro-config");

const config = getDefaultConfig(__dirname);
// The server certificate is bundled as an asset and handed to connectTLS as the CA.
config.resolver.assetExts.push("pem");

module.exports = config;
