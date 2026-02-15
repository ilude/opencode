import { normalize, resolve, BLOCK, ALLOW, type Decision } from "./shell-protect"

// ── Standalone hard-blocks (no path required) ────────────────────────────

const MKFS_RE = /^mkfs\./

const REBOOT_COMMANDS = new Set([
  "shutdown",
  "shutdown.exe",
  "reboot",
  "poweroff",
  "halt",
  "restart-computer",
  "stop-computer",
])

const SYSTEMCTL_POWER = new Set([
  "reboot",
  "poweroff",
  "halt",
  "suspend",
  "hibernate",
])

const FORMAT_COMMANDS = new Set([
  "format-volume",
  "clear-disk",
  "initialize-disk",
])

function standalone(tokens: string[]): Decision | null {
  if (tokens.length === 0) return null
  const cmd = tokens[0].toLowerCase()

  // rm --no-preserve-root
  if (cmd === "rm" && tokens.some((t) => t === "--no-preserve-root"))
    return BLOCK("rm --no-preserve-root disables root safety")

  // mkfs.*
  if (MKFS_RE.test(cmd))
    return BLOCK(`${tokens[0]} formats filesystem`)

  // dd of=/dev/*
  if (cmd === "dd" && tokens.some((t) => t.startsWith("of=/dev/")))
    return BLOCK("dd writes to raw device")

  // format X: (cmd.exe)
  if (cmd === "format" && tokens.length > 1 && /^[a-zA-Z]:$/.test(tokens[1]))
    return BLOCK(`format ${tokens[1]} formats drive`)

  // Format-Volume, Clear-Disk, Initialize-Disk
  if (FORMAT_COMMANDS.has(cmd))
    return BLOCK(`${tokens[0]} is a destructive disk operation`)

  // shutdown/reboot/poweroff/halt/Restart-Computer/Stop-Computer
  if (REBOOT_COMMANDS.has(cmd))
    return BLOCK(`${tokens[0]} would shut down or reboot the machine`)

  // init 0|6, telinit 0|6
  if ((cmd === "init" || cmd === "telinit") && tokens.length > 1 && (tokens[1] === "0" || tokens[1] === "6"))
    return BLOCK(`${tokens[0]} ${tokens[1]} would halt or reboot the machine`)

  // systemctl reboot|poweroff|halt|suspend|hibernate (without a service argument)
  if (cmd === "systemctl" && tokens.length > 1 && SYSTEMCTL_POWER.has(tokens[1].toLowerCase()) && tokens.length <= 2)
    return BLOCK(`systemctl ${tokens[1]} would change machine power state`)

  return null
}

// ── Destructive verb detection ───────────────────────────────────────────

function flags(tokens: string[]): string[] {
  return tokens.filter((t) => t.startsWith("-"))
}

function combined(flag: string): string {
  // For short combined flags like -rf, -fr, -rvf, return the letters after -
  if (flag.startsWith("-") && !flag.startsWith("--") && flag.length > 1)
    return flag.slice(1)
  return ""
}

function hasRecursive(fs: string[]): boolean {
  return fs.some((f) => {
    if (f === "-R" || f === "-r" || f === "--recursive") return true
    const c = combined(f)
    return c.includes("r") || c.includes("R")
  })
}

function hasSFlag(fs: string[]): boolean {
  return fs.some((f) => f.toLowerCase() === "/s")
}

function hasFFlag(fs: string[]): boolean {
  return fs.some((f) => f.toLowerCase() === "/f")
}

function hasRecursePwsh(fs: string[]): boolean {
  return fs.some((f) => f.toLowerCase() === "-recurse")
}

type Verb = {
  paths: (tokens: string[]) => string[]
  reason: string
}

function verb(tokens: string[]): Verb | null {
  const cmd = tokens[0].toLowerCase()
  const fs = flags(tokens)

  // rm with recursive
  if (cmd === "rm" && hasRecursive(fs))
    return {
      paths: (t) => t.slice(1).filter((x) => !x.startsWith("-")),
      reason: "recursive rm on protected path",
    }

  // find with -delete or -exec rm
  if (cmd === "find") {
    const hasDelete = tokens.includes("-delete")
    const hasExecRm = tokens.some((t, i) =>
      (t === "-exec" || t === "-execdir") && tokens[i + 1] && (tokens[i + 1] === "rm" || tokens[i + 1] === "rmdir"),
    )
    if (hasDelete || hasExecRm)
      return {
        // find's search root is non-flag tokens before the first - prefixed token
        paths: (t) => {
          const result: string[] = []
          for (let i = 1; i < t.length; i++) {
            if (t[i].startsWith("-")) break
            result.push(t[i])
          }
          return result
        },
        reason: "find with delete on protected path",
      }
  }

  // shred (always destructive)
  if (cmd === "shred")
    return {
      paths: (t) => t.slice(1).filter((x) => !x.startsWith("-")),
      reason: "shred on protected path",
    }

  // mv (any invocation)
  if (cmd === "mv" || cmd === "move-item" || cmd === "mi" || cmd === "move")
    return {
      paths: (t) => t.slice(1).filter((x) => !x.startsWith("-")),
      reason: "move on protected path",
    }

  // chmod/chown with recursive
  if ((cmd === "chmod" || cmd === "chown") && hasRecursive(fs))
    return {
      paths: (t) => t.slice(1).filter((x) => !x.startsWith("-")),
      reason: `recursive ${cmd} on protected path`,
    }

  // Remove-Item / aliases with -Recurse
  if ((cmd === "remove-item" || cmd === "ri" || cmd === "del" || cmd === "rmdir" || cmd === "erase") && hasRecursePwsh(fs))
    return {
      paths: (t) => t.slice(1).filter((x) => !x.startsWith("-")),
      reason: "recursive Remove-Item on protected path",
    }

  // rd/rmdir (cmd.exe) with /s
  if ((cmd === "rd" || (cmd === "rmdir" && tokens.some((t) => t.toLowerCase() === "/s"))) && hasSFlag(fs.concat(tokens.filter((t) => t.startsWith("/")))))
    return {
      paths: (t) => t.slice(1).filter((x) => !x.startsWith("-") && !x.startsWith("/")),
      reason: "rd /s on protected path",
    }

  // del (cmd.exe) with /s or /f
  if (cmd === "del") {
    const cmdFlags = tokens.filter((t) => t.startsWith("/"))
    if (hasSFlag(cmdFlags) || hasFFlag(cmdFlags))
      return {
        paths: (t) => t.slice(1).filter((x) => !x.startsWith("-") && !x.startsWith("/")),
        reason: "del with destructive flags on protected path",
      }
  }

  return null
}

// ── Critical path matching ───────────────────────────────────────────────

const UNIX_ROOTS = [
  "/",
  "/usr",
  "/bin",
  "/sbin",
  "/boot",
  "/etc",
  "/root",
  "/lib",
  "/lib64",
  "/lib32",
  "/var",
  "/dev",
  "/proc",
  "/sys",
  "/opt",
  "/srv",
  "/snap",
  "/run",
  "/mnt",
  "/media",
  "/home",
  "/nix",
]

const MACOS_ROOTS = [
  "/System",
  "/Library",
  "/Applications",
  "/private",
  "/private/var",
  "/private/etc",
  "/Volumes",
  "/cores",
]

const WIN_ROOTS = [
  "C:\\Windows",
  "C:\\Program Files",
  "C:\\Program Files (x86)",
  "C:\\ProgramData",
  "C:\\Boot",
  "C:\\Recovery",
  "C:\\System Volume Information",
  "C:\\Users",
]

function critical(platform: string): Set<string> {
  const paths: string[] = []

  if (platform !== "win32") {
    paths.push(...UNIX_ROOTS)
    if (platform === "darwin") paths.push(...MACOS_ROOTS)
  }

  if (platform === "win32") {
    paths.push(...WIN_ROOTS)
  }

  return new Set(paths.map((p) => normalize(p, platform)))
}

const DRIVE_ROOT_RE = /^[a-zA-Z]:[/\\]?$/
const GLOB_META_RE = /[*?[]/

function dangerous(
  resolved: string,
  platform: string,
  roots: Set<string>,
): boolean {
  // System root: / or X:\
  if (resolved === normalize("/", platform)) return true
  if (platform === "win32" && DRIVE_ROOT_RE.test(resolved)) return true

  // Exact match against protected paths
  if (roots.has(resolved)) return true

  // Check if resolved is a descendant of a system root (/ or X:\)
  const root = normalize("/", platform)
  if (resolved.startsWith(root) && resolved !== root) {
    // Only block descendants of / itself — other paths are checked exact
  }

  return false
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Check whether a command token array represents a catastrophic operation.
 * Returns block or allow — catastrophic checks never return ask.
 */
export function catastrophic(
  tokens: string[],
  cwd: string,
  platform = process.platform,
): Decision {
  if (tokens.length === 0) return ALLOW

  // 1. Standalone hard-blocks (no path check needed)
  const s = standalone(tokens)
  if (s) return s

  // 2. Destructive verb + critical path
  const v = verb(tokens)
  if (!v) return ALLOW

  const roots = critical(platform)
  const paths = v.paths(tokens)

  for (const raw of paths) {
    // Glob metacharacters in destructive commands -> fail closed
    if (GLOB_META_RE.test(raw)) {
      const resolved = resolve(raw.replace(/[*?[\]]/g, ""), cwd, platform)
      if (resolved && (dangerous(resolved, platform, roots) || roots.has(resolved)))
        return BLOCK(`${v.reason} (glob pattern on system path)`)
      // Also check if it's literally <protected>/*
      const base = raw.replace(/\/?\*.*$/, "").replace(/\\?\*.*$/, "")
      if (base.length > 0) {
        const resolvedBase = resolve(base, cwd, platform)
        if (resolvedBase && (dangerous(resolvedBase, platform, roots) || roots.has(resolvedBase)))
          return BLOCK(`${v.reason} (glob pattern on system path)`)
      }
    }

    const resolved = resolve(raw, cwd, platform)
    if (!resolved) continue
    if (dangerous(resolved, platform, roots))
      return BLOCK(v.reason)
  }

  return ALLOW
}
