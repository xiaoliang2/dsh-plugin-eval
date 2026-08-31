// A deliberately clean plugin: no secrets, no risky patterns.
const VERSION = '1.2.3'

export function run(input) {
  return { ok: true, input, version: VERSION }
}
