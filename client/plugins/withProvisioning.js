const { withProjectBuildGradle } = require('@expo/config-plugins');

module.exports = (config) => withProjectBuildGradle(config, (result) => {
  const marker = '// Wake-on-LAN: Espressif provisioning SDK';
  if (!result.modResults.contents.includes(marker)) {
    result.modResults.contents += `\n${marker}\nallprojects { repositories { maven { url 'https://jitpack.io' } } }\n`;
  }
  return result;
});
