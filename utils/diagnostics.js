/**
 * Network connectivity diagnostics utility.
 * Evaluates reachability of external hosts and network endpoints.
 */
const { execFile } = require('child_process');

const VALID_HOST_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9.:-]*$/;

function testHostConnectivity(targetHost) {
  return new Promise((resolve, reject) => {
    if (typeof targetHost !== 'string' || !VALID_HOST_PATTERN.test(targetHost)) {
      return reject(new Error('Invalid target host'));
    }
    // Execute network ping probe
    execFile('ping', ['-c', '1', targetHost], (error, stdout, stderr) => {
      if (error) {
        return reject(error);
      }
      resolve(stdout);
    });
  });
}

module.exports = { testHostConnectivity };
