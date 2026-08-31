// dsh-plugin-eval — comprehensive pre-install evaluation for DSH plugins.
//
// Registers one model Tool, `plugin_eval`, that runs the static evaluation
// engine against a target plugin (local checkout, GitHub owner/repo, or npm
// package name) and returns a JSON report plus a human-readable summary:
// security scan, footprint/performance benchmark, community review
// aggregation, version compatibility check, and a composite reliability score.

import { defineTool } from '@deepseek-ai/dsh-tools'
import { evaluatePlugin, renderReport } from './engine/index.js'
import { resolveRuntimeFacts } from './engine/runtime.js'

const name = 'plugin-eval'
const inject = ['tools']

function apply(ctx, _config = {}) {
  ctx.tools.register(
    defineTool({
      name: 'plugin_eval',
      description:
        'Evaluate a plugin before installing it (supply-chain check). Targets: a local plugin directory path, a GitHub "owner/repo", or an npm package name. Runs static analysis only — it NEVER executes the target plugin. Returns a JSON report with per-dimension scores (security, compatibility, footprint/performance, community, documentation), a composite 0-100 reliability score with letter grade, a verdict (recommended/acceptable/caution/blocked), and findings with severity. Point it at a local checkout for the deepest scan.',
      parameters: {
        target: {
          type: 'string',
          required: true,
          description: 'Local plugin directory path, GitHub owner/repo, or npm package name to evaluate.',
        },
        allow_network: {
          type: 'boolean',
          description: 'Whether to fetch public GitHub/npm/OSV metadata (default true).',
        },
        dsh_version: {
          type: 'string',
          description: 'Optional override of the running DSH version for peerDependencies checks (default: auto-detected).',
        },
      },
      output: {
        schema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            target: { type: 'string' },
            composite: {
              type: 'object',
              properties: {
                score: { type: 'number' },
                grade: { type: 'string' },
                verdict: { type: 'string' },
              },
            },
            report: { type: 'string' },
          },
        },
        render(_args, value) {
          const text = typeof value?.report === 'string' ? value.report : JSON.stringify(value, null, 2)
          return [{ type: 'text', text }]
        },
      },
      async execute(args, exec) {
        const fs = ctx.get('fs')
        const web = ctx.get('web')
        const runtime = resolveRuntimeFacts(args.dsh_version)
        const result = await evaluatePlugin({
          target: args.target,
          deps: { fs, web },
          runtime,
          opts: {
            allowNetwork: args.allow_network !== false,
            signal: exec?.signal,
          },
        })
        // Keep the JSON small for the model; `report` carries the readable form.
        return {
          target: result.target,
          composite: result.composite,
          report: result.report,
        }
      },
    }),
  )
}

export { name, inject, apply }
