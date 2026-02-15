import path from "path"
import { expand, normalize, BLOCK, ALLOW, type Decision } from "./shell-protect"

// ── Exempt commands (metadata-only, no content exposure) ─────────────────

const EXEMPT = new Set([
  "ls",
  "dir",
  "stat",
  "file",
  "wc",
  "test",
  "[",
  "ssh-keygen",
  "ssh-add",
])

const GIT_EXEMPT_SUB = new Set([
  "check-ignore",
  "ls-files",
  "status",
  "rm",
])

function exempt(tokens: string[]): boolean {
  if (tokens.length === 0) return false
  const cmd = tokens[0].toLowerCase()
  if (EXEMPT.has(cmd)) return true
  if (cmd === "git" && tokens.length > 1) {
    const sub = tokens[1].toLowerCase()
    if (GIT_EXEMPT_SUB.has(sub)) return true
    // git diff --name-only
    if (sub === "diff" && tokens.includes("--name-only")) return true
  }
  return false
}

// ── Protected directory prefixes (always blocked, even inside project) ───

// Absolute paths (expanded from ~ or literal) — prefix-match on normalized path
const DIR_PREFIXES = [
  // SSH/GPG
  "~/.ssh/",
  "~/.gnupg/",
  // Cloud credentials
  "~/.aws/",
  "~/.config/gcloud/",
  "~/.azure/",
  "~/.kube/",
  "~/.docker/",
  // Package manager auth
  "~/.git-credentials",
  "~/.netrc",
  "~/.npmrc",
  "~/.pypirc",
  "~/.config/gh/hosts.yml",
  "~/.vault-token",
  // Windows credential stores
  "C:\\Windows\\System32\\config\\SAM",
  "C:\\Windows\\System32\\config\\SYSTEM",
  "C:\\Windows\\System32\\config\\SECURITY",
  // Linux system credentials
  "/etc/shadow",
  "/etc/shadow-",
  "/etc/master.passwd",
]

// Relative directory names — matched as path segments anywhere in the path
const SEGMENT_DIRS = [
  ".terraform",
  ".vercel",
  ".netlify",
  ".supabase",
  ".git-credentials",
]

// Wildcard directory patterns (contain user-variable segments)
const DIR_WILDCARD = [
  "/Microsoft/Protect/",
  "/Microsoft/Credentials/",
  "/Microsoft/Vault/",
  // Browser credentials
  "/Login Data",
  "/Cookies",
  "/Local State",
  "/logins.json",
  "/key4.db",
  "/cookies.sqlite",
  // Messaging
  "/Discord/Local Storage/leveldb/",
  "/Telegram Desktop/tdata/",
  "/Slack/storage/",
  "/Slack/Cookies",
  "/Signal/sql/",
  "/Signal/config.json",
  // Password managers
  "/1Password/data/",
  "/Bitwarden/data/",
  // Crypto wallets
  "/Bitcoin/wallet.dat",
  "/Bitcoin/wallets/",
  "/Ethereum/keystore/",
]

// ── Glob basename patterns (blocked only outside project) ────────────────

const GLOB_PATTERNS = [
  // GCP service account files
  "-credentials.json",
  "serviceaccount",
  "service-account",
  // SSL/TLS keys
  ".pem",
  ".p12",
  ".pfx",
  ".ppk",
  // Terraform
  ".tfvars",
  // Session files
  ".session",
  // Firebase
  "firebase-adminsdk",
  "serviceaccountkey.json",
  // Database dumps
  "dump.sql",
  "backup.sql",
  ".dump",
  // Password manager databases
  ".kdbx",
  ".kdb",
  // Crypto wallets
  "wallet.dat",
  ".wallet",
  // Env files
  ".env",
]

// ── Build normalized prefix sets at module load ──────────────────────────

function prefixes(platform: string): string[] {
  return DIR_PREFIXES.map((p) => normalize(expand(p), platform))
}

function wildcards(platform: string): string[] {
  return DIR_WILDCARD.map((p) =>
    platform === "win32" || platform === "darwin" ? p.toLowerCase() : p,
  )
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Check whether a command token array accesses zero-access credential paths.
 * Returns block or allow.
 */
export function zero(
  tokens: string[],
  cwd: string,
  project: string,
  platform: string = process.platform,
): Decision {
  if (tokens.length === 0) return ALLOW
  if (exempt(tokens)) return ALLOW

  const pfx = prefixes(platform)
  const wc = wildcards(platform)
  const p = platform === "win32" ? path.win32 : path.posix
  const projNorm = normalize(project, platform)

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i]
    if (token.startsWith("-")) continue

    const expanded = expand(token)
    // Skip unresolvable variable references
    if (expanded.startsWith("$") || expanded.startsWith("%")) continue

    const abs = p.isAbsolute(expanded)
      ? expanded
      : p.resolve(cwd, expanded)
    const norm = normalize(abs, platform)

    // 1. Directory prefix match (always blocks)
    for (const prefix of pfx) {
      if (norm === prefix || norm.startsWith(prefix)) return BLOCK(`access to ${token} is blocked (credential path)`)
    }

    // 2. Segment directory match (e.g. .terraform anywhere in path, blocks outside project)
    const sep = platform === "win32" ? "\\" : "/"
    for (const seg of SEGMENT_DIRS) {
      const segNorm = platform === "win32" || platform === "darwin" ? seg.toLowerCase() : seg
      if (norm.includes(sep + segNorm + sep) || norm.endsWith(sep + segNorm) || norm.includes(sep + segNorm + sep)) {
        if (!norm.startsWith(projNorm + sep) && norm !== projNorm)
          return BLOCK(`access to ${token} is blocked (credential path)`)
      }
    }

    // 3. Wildcard directory match (always blocks)
    for (const pattern of wc) {
      const normalized = platform === "win32" || platform === "darwin"
        ? pattern.replace(/\//g, "\\")
        : pattern
      if (norm.includes(normalized)) return BLOCK(`access to ${token} is blocked (credential path)`)
    }

    // 4. Glob basename match (blocks only outside project)
    const base = p.basename(norm).toLowerCase()
    for (const pattern of GLOB_PATTERNS) {
      if (base.endsWith(pattern) || base === pattern.replace(/^\./, "")) {
        // Check if inside project — project files matching globs are OK
        if (!norm.startsWith(projNorm + p.sep) && norm !== projNorm) {
          return BLOCK(`access to ${token} is blocked (sensitive file pattern)`)
        }
      }
    }
  }

  return ALLOW
}
