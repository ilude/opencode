const MAX_DEPTH = 5

const SHELLS = new Set([
  "bash",
  "sh",
  "zsh",
  "ksh",
  "dash",
])

const SHELL_FLAGS = new Set(["-c"])

const CMD = new Set(["cmd", "cmd.exe"])
const CMD_FLAGS = new Set(["/c", "/k"])

const PWSH = new Set([
  "pwsh",
  "pwsh.exe",
  "powershell",
  "powershell.exe",
])

const PWSH_FLAGS = new Set(["-command", "-c"])

const WSL = new Set(["wsl", "wsl.exe"])

const INTERPRETERS = new Set([
  "python",
  "python3",
  "node",
  "ruby",
  "perl",
])

const INTERPRETER_FLAGS = new Set(["-c", "-e", "--eval"])

const SUDO_FLAGS_WITH_VALUE = new Set(["-u", "-g", "-C", "-D", "-R", "-T"])
const SUDO_FLAGS_NO_VALUE = new Set(["-i", "-s", "-E", "-H", "-n", "-k", "-K", "-b", "-P", "--"])

const XARGS_FLAGS_WITH_VALUE = new Set(["-n", "-I", "-P", "-d", "-L", "-E", "-s"])
const XARGS_FLAGS_NO_VALUE = new Set(["-0", "-t", "-p", "-r", "--no-run-if-empty"])

const SYSTEM_CALL_RE = /(?:os\.system|subprocess\.(?:run|call|Popen)|child_process\.exec(?:Sync)?|execSync|system|exec)\s*\(\s*(['"`])(.*?)\1/

export function tokenize(input: string): string[][] {
  const groups: string[][] = []
  let current: string[] = []
  let i = 0

  while (i < input.length) {
    const ch = input[i]

    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i++
      continue
    }

    if (ch === ";" || ch === "\n") {
      if (current.length > 0) {
        groups.push(current)
        current = []
      }
      i++
      continue
    }

    if (ch === "&" && input[i + 1] === "&") {
      if (current.length > 0) {
        groups.push(current)
        current = []
      }
      i += 2
      continue
    }

    if (ch === "|" && input[i + 1] === "|") {
      if (current.length > 0) {
        groups.push(current)
        current = []
      }
      i += 2
      continue
    }

    if (ch === "|") {
      if (current.length > 0) {
        groups.push(current)
        current = []
      }
      i++
      continue
    }

    if (ch === '"' || ch === "'") {
      const quote = ch
      let token = ""
      i++
      while (i < input.length && input[i] !== quote) {
        if (input[i] === "\\" && quote === '"' && i + 1 < input.length) {
          i++
          token += input[i]
        } else {
          token += input[i]
        }
        i++
      }
      if (i < input.length) i++
      current.push(token)
      continue
    }

    if (ch === "\\") {
      i++
      if (i < input.length) {
        let token = input[i]
        i++
        while (i < input.length && input[i] !== " " && input[i] !== "\t") {
          token += input[i]
          i++
        }
        current.push(token)
      }
      continue
    }

    let token = ""
    while (
      i < input.length &&
      input[i] !== " " &&
      input[i] !== "\t" &&
      input[i] !== "\n" &&
      input[i] !== "\r" &&
      input[i] !== ";" &&
      !(input[i] === "&" && input[i + 1] === "&") &&
      !(input[i] === "|" && input[i + 1] === "|") &&
      !(input[i] === "|" && input[i + 1] !== "|")
    ) {
      if (input[i] === "\\") {
        i++
        if (i < input.length) token += input[i]
      } else {
        token += input[i]
      }
      i++
    }
    if (token.length > 0) current.push(token)
  }

  if (current.length > 0) groups.push(current)
  return groups
}

function payload(tokens: string[], flags: Set<string>): string | undefined {
  for (let i = 1; i < tokens.length; i++) {
    if (flags.has(tokens[i].toLowerCase()) && i + 1 < tokens.length)
      return tokens[i + 1]
  }
  return undefined
}

function direct(tokens: string[]): string[] {
  return tokens.slice(1)
}

function sudo(tokens: string[]): string[] {
  const result: string[] = []
  let i = 1
  while (i < tokens.length) {
    const flag = tokens[i]
    if (flag === "--") {
      i++
      break
    }
    if (SUDO_FLAGS_WITH_VALUE.has(flag)) {
      i += 2
      continue
    }
    if (SUDO_FLAGS_NO_VALUE.has(flag)) {
      i++
      continue
    }
    if (flag.startsWith("-")) {
      i++
      continue
    }
    break
  }
  while (i < tokens.length) {
    result.push(tokens[i])
    i++
  }
  return result
}

function xargs(tokens: string[]): string[] {
  const result: string[] = []
  let i = 1
  while (i < tokens.length) {
    const flag = tokens[i]
    if (XARGS_FLAGS_WITH_VALUE.has(flag)) {
      i += 2
      continue
    }
    if (XARGS_FLAGS_NO_VALUE.has(flag)) {
      i++
      continue
    }
    if (flag.startsWith("-")) {
      i++
      continue
    }
    break
  }
  while (i < tokens.length) {
    result.push(tokens[i])
    i++
  }
  return result
}

function runas(tokens: string[]): string[] {
  let i = 1
  while (i < tokens.length) {
    if (tokens[i].toLowerCase().startsWith("/user:")) {
      i++
      continue
    }
    if (tokens[i].startsWith("/")) {
      i++
      continue
    }
    break
  }
  return tokens.slice(i)
}

function env(tokens: string[]): string[] {
  let i = 1
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]))
    i++
  return tokens.slice(i)
}

function interpreter(tokens: string[], flags: Set<string>): string | undefined {
  const raw = payload(tokens, flags)
  if (!raw) return undefined
  const match = raw.match(SYSTEM_CALL_RE)
  return match ? match[2] : raw
}

function step(tokens: string[]): { tokens: string[], unwrapped: boolean } {
  if (tokens.length === 0) return { tokens, unwrapped: false }

  const name = tokens[0].toLowerCase().replace(/\.exe$/, "")

  if (SHELLS.has(name)) {
    const inner = payload(tokens, SHELL_FLAGS)
    if (inner) return { tokens: tokenize(inner).flat(), unwrapped: true }
  }

  if (CMD.has(tokens[0].toLowerCase())) {
    const inner = payload(tokens, CMD_FLAGS)
    if (inner) return { tokens: tokenize(inner).flat(), unwrapped: true }
  }

  if (PWSH.has(tokens[0].toLowerCase())) {
    const inner = payload(tokens, PWSH_FLAGS)
    if (inner) return { tokens: tokenize(inner).flat(), unwrapped: true }
  }

  if (WSL.has(tokens[0].toLowerCase())) {
    const inner = direct(tokens)
    if (inner.length > 0) return { tokens: inner, unwrapped: true }
  }

  if (tokens[0] === "eval") {
    const rest = tokens.slice(1).join(" ")
    if (rest.length > 0) return { tokens: tokenize(rest).flat(), unwrapped: true }
  }

  if (name === "sudo" || name === "doas") {
    const inner = sudo(tokens)
    if (inner.length > 0) return { tokens: inner, unwrapped: true }
  }

  if (tokens[0].toLowerCase() === "runas") {
    const inner = runas(tokens)
    if (inner.length > 0) return { tokens: inner, unwrapped: true }
  }

  if (INTERPRETERS.has(name)) {
    const inner = interpreter(tokens, INTERPRETER_FLAGS)
    if (inner) return { tokens: tokenize(inner).flat(), unwrapped: true }
  }

  if (name === "xargs") {
    const inner = xargs(tokens)
    if (inner.length > 0) return { tokens: inner, unwrapped: true }
  }

  if (name === "env") {
    const inner = env(tokens)
    if (inner.length > 0) return { tokens: inner, unwrapped: true }
  }

  return { tokens, unwrapped: false }
}

export function unwrap(tokens: string[], depth = MAX_DEPTH): { tokens: string[], unwrapped: boolean } {
  let current = tokens
  let changed = false

  for (let i = 0; i < depth; i++) {
    const result = step(current)
    if (!result.unwrapped) break
    current = result.tokens
    changed = true
  }

  return { tokens: current, unwrapped: changed }
}
