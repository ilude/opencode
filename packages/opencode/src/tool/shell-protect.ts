import path from "path"
import os from "os"

export type Decision = {
  decision: "block" | "ask" | "allow"
  reason?: string
}

export const BLOCK = (reason: string): Decision => ({
  decision: "block",
  reason,
})

export const ASK = (reason: string): Decision => ({
  decision: "ask",
  reason,
})

export const ALLOW: Decision = { decision: "allow" }

export function merge(...decisions: Decision[]): Decision {
  let worst: Decision = ALLOW
  for (const d of decisions) {
    if (d.decision === "block") return d
    if (d.decision === "ask" && worst.decision !== "block") worst = d
  }
  return worst
}

const HOME = os.homedir()

/**
 * Expand shell variables that reference the home directory.
 * Handles ~, $HOME, $env:USERPROFILE, $env:HOME.
 * Returns the token unchanged if no expansion applies.
 */
export function expand(token: string): string {
  if (token === "~") return HOME
  if (token.startsWith("~/") || token.startsWith("~\\"))
    return HOME + token.slice(1)

  const upper = token.toUpperCase()

  if (upper === "$HOME") return HOME
  if (upper.startsWith("$HOME/") || upper.startsWith("$HOME\\"))
    return HOME + token.slice(5)

  if (upper === "$ENV:USERPROFILE" || upper === "$ENV:HOME") return HOME
  if (
    upper.startsWith("$ENV:USERPROFILE/") ||
    upper.startsWith("$ENV:USERPROFILE\\")
  )
    return HOME + token.slice(16)
  if (upper.startsWith("$ENV:HOME/") || upper.startsWith("$ENV:HOME\\"))
    return HOME + token.slice(9)

  return token
}

const win32 = path.win32
const posix = path.posix

function pick(platform: string): typeof path.win32 {
  return platform === "win32" ? win32 : posix
}

/**
 * Normalize a path for comparison:
 * 1. MSYS (/c/...) -> C:/...
 * 2. Cygwin (/cygdrive/c/...) -> C:/...
 * 3. WSL (/mnt/c/...) -> C:/...
 * 4. path.normalize (resolve .., //, trailing slashes)
 * 5. Strip trailing separator
 * 6. Lowercase on win32/darwin (case-insensitive filesystems)
 */
export function normalize(
  p: string,
  platform: string = process.platform,
): string {
  let result = p

  if (platform === "win32") {
    // /cygdrive/X/... -> X:/...
    const cyg = result.match(/^\/cygdrive\/([a-zA-Z])(\/.*)?$/)
    if (cyg) result = `${cyg[1].toUpperCase()}:${cyg[2] || "/"}`

    // /mnt/X/... -> X:/... (WSL)
    const wsl = result.match(/^\/mnt\/([a-zA-Z])(\/.*)?$/)
    if (wsl) result = `${wsl[1].toUpperCase()}:${wsl[2] || "/"}`

    // /X/... -> X:/... (MSYS/Git Bash)
    const msys = result.match(/^\/([a-zA-Z])(\/.*)?$/)
    if (msys) result = `${msys[1].toUpperCase()}:${msys[2] || "/"}`
  }

  result = pick(platform).normalize(result)

  // Strip trailing separator (but preserve root like / or C:\)
  if (result.length > 1 && (result.endsWith("/") || result.endsWith("\\")))
    result = result.slice(0, -1)

  if (platform === "win32" || platform === "darwin") result = result.toLowerCase()

  return result
}

/**
 * Resolve a token to an absolute normalized path.
 * Applies expand + normalize + path.resolve(cwd, ...).
 * Returns null if the token is a variable reference we can't resolve.
 */
export function resolve(
  token: string,
  cwd: string,
  platform: string = process.platform,
): string | null {
  const expanded = expand(token)
  // If still a variable reference after expansion, we can't resolve it
  if (expanded.startsWith("$") || expanded.startsWith("%")) return null
  const p = pick(platform)
  const abs = p.isAbsolute(expanded) ? expanded : p.resolve(cwd, expanded)
  return normalize(abs, platform)
}
