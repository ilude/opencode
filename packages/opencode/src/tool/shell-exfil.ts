import { BLOCK, ASK, ALLOW, type Decision } from "./shell-protect"

// ── Network commands ─────────────────────────────────────────────────────

const NETWORK = new Set([
  "curl",
  "wget",
  "nc",
  "ncat",
  "netcat",
  "telnet",
  "scp",
  "rsync",
  "ftp",
  "sftp",
  "mail",
  "mailx",
  "sendmail",
  "mutt",
  "invoke-webrequest",
  "invoke-restmethod",
  "iwr",
  "irm",
])

const ENCODING = new Set([
  "base64",
  "gzip",
  "tar",
  "zip",
  "xxd",
  "hexdump",
])

const SENSITIVE_SOURCE = new Set([
  "env",
  "printenv",
])

// ── Upload flag detection ────────────────────────────────────────────────

const CURL_UPLOAD = new Set([
  "-d",
  "--data",
  "--data-binary",
  "--data-raw",
  "--data-urlencode",
  "-f",
  "--form",
  "-t",
  "--upload-file",
])

const WGET_UPLOAD = new Set([
  "--post-file",
  "--post-data",
])

function hasUpload(cmd: string, tokens: string[]): boolean {
  if (cmd === "curl")
    return tokens.some((t) => CURL_UPLOAD.has(t.toLowerCase()))
  if (cmd === "wget")
    return tokens.some((t) => WGET_UPLOAD.has(t.toLowerCase()))
  // PowerShell: -Method POST/PUT + -Body/-InFile
  if (cmd === "invoke-webrequest" || cmd === "invoke-restmethod" || cmd === "iwr" || cmd === "irm") {
    let method = ""
    for (let i = 0; i < tokens.length; i++) {
      if (tokens[i].toLowerCase() === "-method" && i + 1 < tokens.length)
        method = tokens[i + 1].toLowerCase()
    }
    if (method === "post" || method === "put")
      return tokens.some((t) => t.toLowerCase() === "-body" || t.toLowerCase() === "-infile")
  }
  return false
}

// ── Reverse shell detection ──────────────────────────────────────────────

function reverseShell(tokens: string[]): boolean {
  const cmd = tokens[0].toLowerCase()
  if (cmd === "nc" || cmd === "ncat" || cmd === "netcat")
    return tokens.some((t) => t === "-e")
  return false
}

// ── Trusted host detection ───────────────────────────────────────────────

const PRIVATE_RE = [
  /^127\.\d+\.\d+\.\d+$/,
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
]

function host(tokens: string[]): string | null {
  for (const t of tokens) {
    if (t.startsWith("-")) continue
    // URL format
    const match = t.match(/^https?:\/\/([^/:]+)/)
    if (match) return match[1]
    // /dev/tcp/host/port
    const tcp = t.match(/^\/dev\/(?:tcp|udp)\/([^/]+)/)
    if (tcp) return tcp[1]
    // user@host:path (scp/rsync)
    const scp = t.match(/^(?:[^@]+@)?([^:]+):/)
    if (scp && !scp[1].includes("/") && !scp[1].includes("\\")) return scp[1]
  }
  return null
}

function trusted(h: string | null): boolean {
  if (!h) return false
  if (h === "localhost" || h === "::1") return true
  return PRIVATE_RE.some((re) => re.test(h))
}

// ── DNS exfil detection ──────────────────────────────────────────────────

const DNS = new Set(["dig", "nslookup", "host", "resolve-dnsname", "ping"])

function dns(tokens: string[]): boolean {
  if (!DNS.has(tokens[0].toLowerCase())) return false
  // Check for subexpression tokens or suspiciously constructed hostnames
  return tokens.some((t, i) =>
    i > 0 && !t.startsWith("-") && (t.includes("$(") || t.includes("`") || (t.split(".").length > 3)),
  )
}

// ── File transfer detection ──────────────────────────────────────────────

const TRANSFER = new Set(["scp", "rsync", "ftp", "sftp"])

function transfer(tokens: string[]): boolean {
  const cmd = tokens[0].toLowerCase()
  if (!TRANSFER.has(cmd)) return false
  // Check for remote destination (user@host:path)
  return tokens.some((t, i) =>
    i > 0 && !t.startsWith("-") && /^(?:[^@]+@)?[^:]+:./.test(t),
  )
}

// ── Cloud upload detection ───────────────────────────────────────────────

function cloud(tokens: string[]): boolean {
  if (tokens.length < 3) return false
  const cmd = tokens[0].toLowerCase()
  const sub = tokens[1]?.toLowerCase()

  if (cmd === "aws" && sub === "s3" && ["cp", "sync", "mv"].includes(tokens[2]?.toLowerCase()))
    return tokens.some((t) => t.startsWith("s3://"))
  if (cmd === "gsutil" && ["cp", "rsync"].includes(sub))
    return tokens.some((t) => t.startsWith("gs://"))
  if (cmd === "az" && sub === "storage")
    return true
  if (cmd === "azcopy" && sub === "copy")
    return true
  if (cmd === "rclone" && ["copy", "sync", "move"].includes(sub))
    return true
  return false
}

// ── Email detection ──────────────────────────────────────────────────────

const EMAIL = new Set(["mail", "mailx", "sendmail", "mutt"])

// ── Bash /dev/tcp detection ──────────────────────────────────────────────

function devTcp(tokens: string[]): boolean {
  return tokens.some((t) => t.includes("/dev/tcp/") || t.includes("/dev/udp/"))
}

// ── Sensitive file read detection ────────────────────────────────────────

const SENSITIVE_EXT = new Set([".env", ".pem", ".key", ".crt"])

function sensitiveRead(tokens: string[]): boolean {
  const cmd = tokens[0].toLowerCase()
  if (cmd !== "cat" && cmd !== "type" && cmd !== "get-content") return false
  return tokens.some((t, i) => {
    if (i === 0 || t.startsWith("-")) return false
    const lower = t.toLowerCase()
    return SENSITIVE_EXT.has("." + lower.split(".").pop())
  })
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Check a single command for exfiltration indicators.
 * Pipeline context is optional — when provided, cross-command analysis is enabled.
 */
export function exfiltration(
  tokens: string[],
  pipeline?: string[][],
): Decision {
  if (tokens.length === 0) return ALLOW
  const cmd = tokens[0].toLowerCase()

  // Reverse shell — always block
  if (reverseShell(tokens))
    return BLOCK("reverse shell detected (nc -e)")

  // /dev/tcp or /dev/udp
  if (devTcp(tokens))
    return ASK("/dev/tcp or /dev/udp network access detected")

  // DNS exfiltration
  if (dns(tokens))
    return ASK("DNS query with constructed hostname — possible exfiltration")

  // Network commands
  if (NETWORK.has(cmd)) {
    const h = host(tokens)
    if (trusted(h)) return ALLOW

    // Check pipeline for sensitive source -> network sink
    if (pipeline && pipeline.length > 1) {
      const hasSensitive = pipeline.some((segment) =>
        segment.length > 0 && SENSITIVE_SOURCE.has(segment[0].toLowerCase()),
      )
      if (hasSensitive) return BLOCK("sensitive data piped to network command")
    }

    if (hasUpload(cmd, tokens))
      return ASK("data upload detected")

    // File transfer with remote destination
    if (transfer(tokens))
      return ASK("file transfer to remote host detected")

    // Email
    if (EMAIL.has(cmd))
      return ASK("email command detected — potential data exfiltration")
  }

  // Cloud upload
  if (cloud(tokens))
    return ASK("cloud storage upload detected")

  // Pipeline: encoding -> network
  if (pipeline && pipeline.length > 1) {
    const hasEncoding = pipeline.some((s) => s.length > 0 && ENCODING.has(s[0].toLowerCase()))
    const hasNetwork = pipeline.some((s) => s.length > 0 && NETWORK.has(s[0].toLowerCase()))
    if (hasEncoding && hasNetwork)
      return ASK("encoding before network transmission")
  }

  // Sensitive file in pipeline
  if (sensitiveRead(tokens) && pipeline && pipeline.length > 1)
    return ASK("sensitive file in pipeline")

  return ALLOW
}
