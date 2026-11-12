/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const placeholderPrefix = 'PLACEHOLDER_'
const nodeVersion = '20.20.2'
const cacheRoot = path.join(os.tmpdir(), 'heroku-deploy-supply-chain')

if (process.env.HEROKU_SUPPLY_CHAIN_INNER === '1') {
  writeResult(runJob(JSON.parse(fs.readFileSync(process.env.HEROKU_SUPPLY_CHAIN_CONFIG, 'utf8'))))
} else {
  const workflows = loadWorkflows(repoRoot)
  const jobs = workflows.flatMap(workflow => workflow.jobs.map(job => ({ workflow: workflow.file, ...job })))
  const targets = jobs.filter(job => job.name === 'heroku' || job.steps.some(step => isPipedInstaller(step.run)))
  ensureNodeBinary()
  for (const job of targets) {
    for (const step of job.steps) {
      const pinned = typeof step.uses === 'string' ? parseUses(step.uses) : null
      if (pinned) ensureAction(pinned.repo, pinned.sha)
    }
  }

  for (const ref of ['refs/heads/master', 'refs/heads/develop']) {
    test(`push ${ref}: a replaced Heroku installer must not observe the deploy API key`, { timeout: 180000 }, () => {
      for (const job of targets) {
        const observed = runScenario(job, ref, 'malicious')
        assert.deepEqual(observed, [], `${job.workflow} job ${job.name} let installer-controlled code observe the deploy API key via ${observed.join(', ')}`)
      }
    })

    test(`push ${ref}: checksummed installer bytes must be the bytes that run`, { timeout: 180000 }, () => {
      for (const job of targets) {
        const observed = runScenario(job, ref, 'bound')
        assert.deepEqual(observed, [], `${job.workflow} job ${job.name} executed installer bytes that were not the checksummed bytes and observed the deploy API key via ${observed.join(', ')}`)
      }
    })
  }
}

function runScenario (job, ref, mode) {
  const state = fs.mkdtempSync(path.join(os.tmpdir(), 'heroku-job-'))
  const github = {
    repository: 'juice-shop/juice-shop',
    repository_owner: 'juice-shop',
    event_name: 'push',
    ref,
    ref_name: ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref,
    sha: '1618a611b173b4bf114028e6e02549950606e29d'
  }
  if (job.if && evalIf(job.if, github) === false) {
    fs.rmSync(state, { recursive: true, force: true })
    return []
  }
  const nodeBin = ensureNodeBinary()
  fs.mkdirSync(path.join(state, 'bin'), { recursive: true })
  fs.writeFileSync(path.join(state, 'planted.sh'), plantedScript(path.join(state, 'marker')), { mode: 0o755 })
  fs.writeFileSync(path.join(state, 'malicious.sh'), installerScript(state, true), { mode: 0o755 })
  fs.writeFileSync(path.join(state, 'benign.sh'), installerScript(state, false), { mode: 0o755 })
  fs.writeFileSync(path.join(state, 'fetch-count'), '0')
  fs.writeFileSync(path.join(state, 'curl-wrapper.sh'), curlWrapper(state), { mode: 0o755 })
  fs.copyFileSync('/usr/bin/curl', path.join(state, 'curl.real'))
  fs.chmodSync(path.join(state, 'curl.real'), 0o755)
  const policy = mode === 'malicious' || !jobHasChecksum(job) ? 'malicious' : 'toctou'
  fs.writeFileSync(path.join(state, 'policy'), policy)
  const steps = job.steps.map(step => rewriteStep(step, policy, path.join(state, 'benign.sh')))
  const config = {
    state,
    nodeBin,
    ref,
    github,
    steps,
    env: { ...job.env },
    workspace: path.join(state, 'workspace'),
    home: path.join(state, 'home')
  }
  fs.mkdirSync(config.workspace, { recursive: true })
  fs.mkdirSync(config.home, { recursive: true })
  const configPath = path.join(state, 'config.json')
  fs.writeFileSync(configPath, JSON.stringify(config))
  const mounts = ['/usr/bin/curl', '/bin/curl'].filter(candidate => fs.existsSync(candidate))
  const mountScript = mounts.map(target => `mount --bind "$1" ${target}`).join(' && ')
  const inner = spawnSync('unshare', [
    '--user', '--map-root-user', '--mount',
    'bash', '-c',
    `${mountScript} && exec "$2" "$3"`,
    'bash',
    path.join(state, 'curl-wrapper.sh'),
    process.execPath,
    fileURLToPath(import.meta.url)
  ], {
    env: {
      HEROKU_SUPPLY_CHAIN_INNER: '1',
      HEROKU_SUPPLY_CHAIN_CONFIG: configPath,
      PATH: process.env.PATH,
      TMPDIR: os.tmpdir(),
      LANG: 'C.UTF-8',
      HOME: config.home
    },
    encoding: 'utf8'
  })
  let result
  try {
    result = JSON.parse(fs.readFileSync(path.join(state, 'result.json'), 'utf8'))
  } catch {
    throw new Error(redact(`job harness failed\n${inner.stderr || ''}\n${inner.stdout || ''}`))
  } finally {
    fs.rmSync(path.join(config.home, '.netrc'), { force: true })
    fs.rmSync(state, { recursive: true, force: true })
  }
  if (result.error) throw new Error(redact(result.error))
  return result.observed
}

function runJob (config) {
  const observed = []
  try {
    fs.mkdirSync(config.workspace, { recursive: true })
    const git = (args) => {
      const result = spawnSync('git', args, {
        cwd: config.workspace,
        env: baseEnv(config, []),
        encoding: 'utf8'
      })
      if (result.status !== 0) {
        throw new Error(`git ${args.join(' ')} failed`)
      }
    }
    git(['init', '-b', 'master'])
    git(['config', 'user.email', 'supply-chain-test@example.com'])
    git(['config', 'user.name', 'supply-chain-test'])
    fs.writeFileSync(path.join(config.workspace, 'README'), 'workspace')
    git(['add', 'README'])
    git(['commit', '-m', 'init'])
    const prepend = []
    const env = { ...config.env }
    let jobOk = true
    for (const step of config.steps) {
      if (!stepRuns(step.if, jobOk)) continue
      const pathFile = path.join(config.state, `path-${prepend.length}-${Math.random().toString(16).slice(2)}`)
      const envFile = path.join(config.state, `env-${prepend.length}-${Math.random().toString(16).slice(2)}`)
      fs.writeFileSync(pathFile, '')
      fs.writeFileSync(envFile, '')
      const stepEnv = {
        ...baseEnv(config, prepend),
        ...stringRecord(env),
        GITHUB_PATH: pathFile,
        GITHUB_ENV: envFile,
        GITHUB_REF: config.ref,
        GITHUB_WORKSPACE: config.workspace,
        GITHUB_REPOSITORY: config.github.repository,
        GITHUB_EVENT_NAME: config.github.event_name,
        GITHUB_SHA: config.github.sha
      }
      let status = 0
      if (typeof step.run === 'string') {
        status = runShell(config, step.run, stepEnv)
      } else if (typeof step.uses === 'string' && step.uses.startsWith('actions/checkout@')) {
        status = 0
      } else if (typeof step.uses === 'string') {
        status = runAction(config, step, stepEnv, env)
      }
      Object.assign(env, readEnvFile(envFile))
      for (const line of fs.readFileSync(pathFile, 'utf8').split('\n')) {
        if (line === '') continue
        const existing = prepend.indexOf(line)
        if (existing >= 0) prepend.splice(existing, 1)
        prepend.push(line)
      }
      if (status !== 0) jobOk = false
    }
    if (fs.existsSync(path.join(config.state, 'marker'))) {
      for (const line of fs.readFileSync(path.join(config.state, 'marker'), 'utf8').split('\n')) {
        if (line !== '') observed.push(line)
      }
    }
    return { observed: [...new Set(observed)] }
  } catch (error) {
    return { observed, error: error.stack || String(error) }
  }
}

function runShell (config, script, stepEnv) {
  const scriptPath = path.join(config.state, `step-${crypto.randomBytes(4).toString('hex')}.sh`)
  fs.writeFileSync(scriptPath, script)
  const bash = resolveBash(stepEnv.PATH) || '/bin/bash'
  const result = spawnSync(bash, ['--noprofile', '--norc', '-e', '-o', 'pipefail', scriptPath], {
    cwd: config.workspace,
    env: stepEnv,
    encoding: 'utf8'
  })
  return result.status === null ? 1 : result.status
}

function runAction (config, step, stepEnv, env) {
  const pinned = parseUses(step.uses)
  if (!pinned) return 0
  const actionDir = ensureAction(pinned.repo, pinned.sha)
  const manifest = JSON.parse(spawnSync('python3', ['-c', actionManifestPy(), path.join(actionDir, 'action.yml')], {
    encoding: 'utf8'
  }).stdout)
  if (!String(manifest.using || '').startsWith('node')) {
    if (stepMentionsSecret(step)) fs.appendFileSync(path.join(config.state, 'marker'), 'unexecuted-secret-step\n')
    return 0
  }
  const inputs = { ...manifest.defaults }
  for (const [key, value] of Object.entries(step.with || {})) {
    inputs[key] = substitute(String(value), { env, github: config.github })
  }
  const actionEnv = { ...stepEnv }
  for (const [key, value] of Object.entries(inputs)) {
    actionEnv[`INPUT_${key.replace(/ /g, '_').toUpperCase()}`] = value == null ? '' : String(value)
  }
  const runtime = manifest.using === 'node20' ? config.nodeBin : ''
  if (runtime === '') {
    fs.appendFileSync(path.join(config.state, 'marker'), 'unexecuted-node-runtime\n')
    return 0
  }
  const result = spawnSync(runtime, [path.join(actionDir, manifest.main || 'index.js')], {
    cwd: config.workspace,
    env: actionEnv,
    encoding: 'utf8'
  })
  return result.status === null ? 1 : result.status
}

function stringRecord (values) {
  const out = {}
  for (const [key, value] of Object.entries(values || {})) {
    out[key] = value == null ? '' : String(value)
  }
  return out
}

function baseEnv (config, prepend) {
  const front = [...prepend].reverse()
  return {
    PATH: [...front, process.env.PATH].filter(Boolean).join(':'),
    HOME: config.home,
    TMPDIR: os.tmpdir(),
    LANG: 'C.UTF-8',
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'safe.directory',
    GIT_CONFIG_VALUE_0: '*',
    GIT_AUTHOR_NAME: 'supply-chain-test',
    GIT_AUTHOR_EMAIL: 'supply-chain-test@example.com',
    GIT_COMMITTER_NAME: 'supply-chain-test',
    GIT_COMMITTER_EMAIL: 'supply-chain-test@example.com',
    GIT_TERMINAL_PROMPT: '0'
  }
}

function resolveBash (pathValue) {
  for (const dir of pathValue.split(':')) {
    const candidate = path.join(dir, 'bash')
    if (fs.existsSync(candidate)) return candidate
  }
  return ''
}

function stepRuns (stepIf, jobOk) {
  if (!stepIf) return jobOk
  if (stepIf.includes('always()')) return true
  if (stepIf.includes('failure()') && !stepIf.includes('success()')) return !jobOk
  return jobOk
}

function readEnvFile (file) {
  const text = fs.readFileSync(file, 'utf8')
  const values = {}
  let index = 0
  const readLine = () => {
    if (index >= text.length) return null
    const next = text.indexOf('\n', index)
    if (next < 0) {
      const line = text.slice(index)
      index = text.length
      return line
    }
    const line = text.slice(index, next)
    index = next + 1
    return line
  }
  let line = readLine()
  while (line !== null) {
    if (line !== '') {
      const equals = line.indexOf('=')
      const heredoc = line.indexOf('<<')
      if (equals >= 0 && (heredoc < 0 || equals < heredoc)) {
        values[line.slice(0, equals)] = line.slice(equals + 1)
      } else if (heredoc >= 0) {
        const key = line.slice(0, heredoc)
        const delimiter = line.slice(heredoc + 2)
        const start = index
        let end = index
        let current = readLine()
        while (current !== delimiter) {
          if (current === null) throw new Error('GITHUB_ENV delimiter was not closed')
          end = index - 1
          current = readLine()
        }
        values[key] = end > start ? text.slice(start, end) : ''
      }
    }
    line = readLine()
  }
  return values
}

function substitute (value, ctx) {
  return value.replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_, expression) => {
    const secret = /^secrets\.([A-Za-z0-9_]+)$/.exec(expression)
    if (secret) return placeholderPrefix + secret[1]
    const env = /^env\.([A-Za-z0-9_]+)$/.exec(expression)
    if (env) return ctx.env[env[1]] ?? ''
    const github = /^github\.([A-Za-z0-9_]+)$/.exec(expression)
    if (github) return ctx.github[github[1]] ?? ''
    return ''
  })
}

function evalIf (expression, github) {
  try {
    const tokens = tokenize(expression)
    let index = 0
    const peek = () => tokens[index]
    const parsePrimary = () => {
      const token = peek()
      if (token === '(') {
        index += 1
        const value = parseOr()
        if (tokens[index] !== ')') throw new Error('paren')
        index += 1
        return value
      }
      if (token && typeof token === 'object') {
        index += 1
        return token.s
      }
      if (token === 'true') {
        index += 1
        return true
      }
      if (token === 'false') {
        index += 1
        return false
      }
      if (typeof token === 'string' && token.startsWith('github.')) {
        index += 1
        return github[token.slice('github.'.length)] ?? ''
      }
      throw new Error('primary')
    }
    const parseEq = () => {
      const left = parsePrimary()
      if (peek() === '==' || peek() === '!=') {
        const op = tokens[index]
        index += 1
        const right = parsePrimary()
        const same = left === right
        return op === '==' ? same : !same
      }
      return left
    }
    const parseAnd = () => {
      let left = parseEq()
      while (peek() === '&&') {
        index += 1
        left = Boolean(left) && Boolean(parseEq())
      }
      return left
    }
    const parseOr = () => {
      let left = parseAnd()
      while (peek() === '||') {
        index += 1
        left = Boolean(left) || Boolean(parseAnd())
      }
      return left
    }
    const value = parseOr()
    if (index !== tokens.length) throw new Error('trailing')
    return Boolean(value)
  } catch {
    return null
  }
}

function tokenize (input) {
  const tokens = []
  let index = 0
  while (index < input.length) {
    if (/\s/.test(input[index])) {
      index += 1
      continue
    }
    if (input.startsWith('&&', index) || input.startsWith('||', index) || input.startsWith('==', index) || input.startsWith('!=', index)) {
      tokens.push(input.slice(index, index + 2))
      index += 2
      continue
    }
    if (input[index] === '(' || input[index] === ')') {
      tokens.push(input[index])
      index += 1
      continue
    }
    if (input[index] === "'") {
      const end = input.indexOf("'", index + 1)
      if (end < 0) throw new Error('quote')
      tokens.push({ s: input.slice(index + 1, end) })
      index = end + 1
      continue
    }
    const match = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(input.slice(index))
    if (!match) throw new Error('token')
    tokens.push(match[0])
    index += match[0].length
  }
  return tokens
}

function isPipedInstaller (run) {
  return typeof run === 'string' && /\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(ba)?sh\b/.test(run)
}

function jobHasChecksum (job) {
  return job.steps.some(step => typeof step.run === 'string' && /\bsha(256|512)sum\b|\bshasum\b/.test(step.run))
}

function rewriteStep (step, policy, benignPath) {
  if (policy !== 'toctou' || typeof step.run !== 'string') return step
  if (!/\bsha256sum\b|\bshasum\b/.test(step.run)) return step
  const hash = crypto.createHash('sha256').update(fs.readFileSync(benignPath)).digest('hex')
  return { ...step, run: step.run.replace(/\b[a-fA-F0-9]{64}\b/g, hash) }
}

function installerScript (state, malicious) {
  const bin = path.join(state, 'bin')
  const planted = path.join(state, 'planted.sh')
  if (!malicious) {
    return `#!/bin/sh
mkdir -p '${bin}'
printf '%s\\n' '#!/bin/sh' 'exit 0' > '${bin}/heroku'
chmod +x '${bin}/heroku'
printf '%s\\n' '${bin}' >> "$GITHUB_PATH"
`
  }
  return `#!/bin/sh
mkdir -p '${bin}'
cp '${planted}' '${bin}/heroku'
cp '${planted}' '${bin}/cat'
chmod +x '${bin}/heroku' '${bin}/cat'
printf '%s\\n' '${bin}' >> "$GITHUB_PATH"
`
}

function plantedScript (marker) {
  return `#!/bin/sh
marker='${marker}'
name=$(basename "$0")
record() {
  printf '%s\\n' "$1" >> "$marker"
}
if [ "$name" = "cat" ]; then
  tmp=$(mktemp)
  /bin/cat > "$tmp"
  if grep -F -q '${placeholderPrefix}' "$tmp"; then
    record cat-stdin
  fi
  /bin/cat "$tmp"
  rm -f "$tmp"
fi
if tr '\\0' '\\n' < "/proc/$PPID/cmdline" | grep -F -q '${placeholderPrefix}'; then
  record "$name-parent-cmdline"
fi
if [ -f "$HOME/.netrc" ] && grep -F -q '${placeholderPrefix}' "$HOME/.netrc"; then
  record "$name-netrc"
fi
python3 - "$marker" "$name" << 'PY'
import sys
marker, name = sys.argv[1], sys.argv[2]
prefix = ${JSON.stringify(placeholderPrefix)}
import os
for key, val in os.environ.items():
    if prefix in str(val):
        with open(marker, "a") as handle:
            handle.write(name + "-env\\n")
        break
PY
exit 0
`
}

function curlWrapper (state) {
  return `#!/bin/bash
state='${state}'
out=""
url=""
args=("$@")
i=0
while [ $i -lt \${#args[@]} ]; do
  a="\${args[$i]}"
  case "$a" in
    -o|--output)
      i=$((i + 1))
      out="\${args[$i]}"
      ;;
    --output=*)
      out="\${a#--output=}"
      ;;
    http://*|https://*)
      url="$a"
      ;;
    -*)
      flags="\${a#-}"
      if [ "\${flags%o}" != "$flags" ]; then
        rest="\${flags##*o}"
        if [ -n "$rest" ]; then
          out="$rest"
        else
          i=$((i + 1))
          out="\${args[$i]}"
        fi
      fi
      ;;
  esac
  i=$((i + 1))
done
if [ -z "$url" ]; then
  exec "$state/curl.real" "$@"
fi
count="$state/fetch-count"
n=$(cat "$count")
n=$((n + 1))
printf '%s' "$n" > "$count"
policy=$(cat "$state/policy")
body="$state/malicious.sh"
if [ "$policy" = "toctou" ] && [ "$n" -eq 1 ]; then
  body="$state/benign.sh"
fi
target="$out$url"
if printf '%s' "$target" | grep -E -q 'sha256|sha512|checksum|\\.digest'; then
  hash=$(sha256sum "$body" | awk '{print $1}')
  name=$(basename "\${out:-artifact}")
  name="\${name%.sha256}"
  name="\${name%.sha512}"
  payload=$(printf '%s  %s\\n' "$hash" "$name")
  if [ -n "$out" ]; then
    printf '%s' "$payload" > "$out"
  else
    printf '%s' "$payload"
  fi
  exit 0
fi
if [ -n "$out" ]; then
  cp "$body" "$out"
else
  cat "$body"
fi
`
}

function loadWorkflows (root) {
  const program = `
import json, pathlib, yaml
root = pathlib.Path(${JSON.stringify(root)})
workflows = []
for path in sorted((root / '.github' / 'workflows').glob('*.yml')):
    data = yaml.safe_load(path.read_text()) or {}
    env = data.get('env') or {}
    jobs = []
    for name, job in (data.get('jobs') or {}).items():
        steps = []
        for step in job.get('steps') or []:
            item = {
                'name': step.get('name'),
                'if': step.get('if'),
                'uses': step.get('uses'),
                'run': step.get('run'),
                'with': step.get('with') or {}
            }
            steps.append(item)
        jobs.append({
            'name': name,
            'if': job.get('if'),
            'env': {**({} if not isinstance(env, dict) else env), **(job.get('env') or {})},
            'steps': steps
        })
    workflows.append({'file': str(path.relative_to(root)), 'jobs': jobs})
print(json.dumps(workflows))
`
  const result = spawnSync('python3', ['-c', program], { encoding: 'utf8' })
  if (result.status !== 0) throw new Error(result.stderr)
  return JSON.parse(result.stdout)
}

function ensureNodeBinary () {
  const dest = path.join(cacheRoot, `node-v${nodeVersion}`)
  const bin = path.join(dest, 'bin', 'node')
  if (fs.existsSync(bin)) return bin
  fs.mkdirSync(cacheRoot, { recursive: true })
  const tar = path.join(cacheRoot, `node-v${nodeVersion}.tar.xz`)
  if (!fs.existsSync(tar)) {
    const download = spawnSync('curl', ['-fsSL', '-o', tar, `https://nodejs.org/dist/v${nodeVersion}/node-v${nodeVersion}-linux-x64.tar.xz`], { encoding: 'utf8' })
    if (download.status !== 0) throw new Error('node download failed')
  }
  fs.mkdirSync(dest, { recursive: true })
  const extract = spawnSync('tar', ['-xJf', tar, '-C', dest, '--strip-components=1'], { encoding: 'utf8' })
  if (extract.status !== 0) throw new Error('node extract failed')
  return bin
}

function ensureAction (repo, sha) {
  const dest = path.join(cacheRoot, `${repo.replace('/', '-')}-${sha}`)
  const marker = path.join(dest, 'action.yml')
  if (fs.existsSync(marker)) return dest
  fs.mkdirSync(cacheRoot, { recursive: true })
  const tar = path.join(cacheRoot, `${sha}.tar.gz`)
  if (!fs.existsSync(tar)) {
    const download = spawnSync('curl', ['-fsSL', '-o', tar, `https://codeload.github.com/${repo}/tar.gz/${sha}`], { encoding: 'utf8' })
    if (download.status !== 0) throw new Error('action download failed')
  }
  const parent = fs.mkdtempSync(path.join(cacheRoot, 'extract-'))
  const extract = spawnSync('tar', ['-xzf', tar, '-C', parent], { encoding: 'utf8' })
  if (extract.status !== 0) throw new Error('action extract failed')
  const [folder] = fs.readdirSync(parent)
  fs.renameSync(path.join(parent, folder), dest)
  return dest
}

function parseUses (uses) {
  const match = /^([^@]+)@([0-9a-f]{40})$/.exec(uses.trim())
  if (!match) return null
  const repo = match[1].split('/').slice(0, 2).join('/')
  return { repo, sha: match[2] }
}

function stepMentionsSecret (step) {
  return JSON.stringify(step.with || {}).includes('secrets.')
}

function actionManifestPy () {
  return `
import json, sys, yaml
data = yaml.safe_load(open(sys.argv[1])) or {}
runs = data.get("runs") or {}
defaults = {}
for key, spec in (data.get("inputs") or {}).items():
    if isinstance(spec, dict) and "default" in spec:
        value = spec["default"]
        if isinstance(value, bool):
            defaults[key] = "true" if value else "false"
        elif value is None:
            defaults[key] = ""
        else:
            defaults[key] = str(value)
print(json.dumps({"using": runs.get("using"), "main": runs.get("main"), "defaults": defaults}))
`
}

function writeResult (result) {
  const config = JSON.parse(fs.readFileSync(process.env.HEROKU_SUPPLY_CHAIN_CONFIG, 'utf8'))
  fs.writeFileSync(path.join(config.state, 'result.json'), JSON.stringify(result))
}

function redact (text) {
  return String(text).replace(/PLACEHOLDER_[A-Za-z0-9_]+/g, '[redacted]')
}
