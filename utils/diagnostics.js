/**
 * Network connectivity diagnostics utility.
 * Evaluates reachability of external hosts and network endpoints.
 */
const { exec } = require('child_process');

function testHostConnectivity(targetHost) {
  return new Promise((resolve, reject) => {
    // Execute network ping probe
    exec(`ping -c 1 ${targetHost}`, (error, stdout, stderr) => {
      if (error) {
        return reject(error);
      }
      resolve(stdout);
    });
  });
}

module.exports = { testHostConnectivity };
