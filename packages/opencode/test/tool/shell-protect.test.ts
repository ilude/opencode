import { describe, expect, test } from "bun:test"
import {
  expand,
  normalize,
  resolve,
  merge,
  BLOCK,
  ASK,
  ALLOW,
} from "../../src/tool/shell-protect"
import os from "os"

const HOME = os.homedir()
const IS_WIN = process.platform === "win32"
const IS_MAC = process.platform === "darwin"

describe("Decision helpers", () => {
  test("BLOCK returns block decision with reason", () => {
    const d = BLOCK("dangerous")
    expect(d.decision).toBe("block")
    expect(d.reason).toBe("dangerous")
  })

  test("ASK returns ask decision with reason", () => {
    const d = ASK("suspicious")
    expect(d.decision).toBe("ask")
    expect(d.reason).toBe("suspicious")
  })

  test("ALLOW returns allow decision", () => {
    expect(ALLOW.decision).toBe("allow")
    expect(ALLOW.reason).toBeUndefined()
  })
})

describe("merge", () => {
  test("all allow returns allow", () => {
    expect(merge(ALLOW, ALLOW, ALLOW).decision).toBe("allow")
  })

  test("ask beats allow", () => {
    expect(merge(ALLOW, ASK("x"), ALLOW).decision).toBe("ask")
  })

  test("block beats ask", () => {
    expect(merge(ASK("x"), BLOCK("y"), ALLOW).decision).toBe("block")
  })

  test("first block wins", () => {
    const d = merge(BLOCK("first"), BLOCK("second"))
    expect(d.decision).toBe("block")
    expect(d.reason).toBe("first")
  })

  test("empty returns allow", () => {
    expect(merge().decision).toBe("allow")
  })

  test("single block returns block", () => {
    expect(merge(BLOCK("only")).decision).toBe("block")
  })
})

describe("expand", () => {
  test("~ expands to home", () => {
    expect(expand("~")).toBe(HOME)
  })

  test("~/path expands", () => {
    expect(expand("~/foo/bar")).toBe(HOME + "/foo/bar")
  })

  test("~\\path expands on backslash", () => {
    expect(expand("~\\foo")).toBe(HOME + "\\foo")
  })

  test("$HOME expands", () => {
    expect(expand("$HOME")).toBe(HOME)
  })

  test("$home expands (case insensitive)", () => {
    expect(expand("$home")).toBe(HOME)
  })

  test("$HOME/path expands", () => {
    expect(expand("$HOME/.ssh")).toBe(HOME + "/.ssh")
  })

  test("$HOME\\path expands", () => {
    expect(expand("$HOME\\.ssh")).toBe(HOME + "\\.ssh")
  })

  test("$env:USERPROFILE expands", () => {
    expect(expand("$env:USERPROFILE")).toBe(HOME)
  })

  test("$env:userprofile expands (case insensitive)", () => {
    expect(expand("$env:userprofile")).toBe(HOME)
  })

  test("$env:USERPROFILE/path expands", () => {
    expect(expand("$env:USERPROFILE/.aws")).toBe(HOME + "/.aws")
  })

  test("$env:HOME expands", () => {
    expect(expand("$env:HOME")).toBe(HOME)
  })

  test("$env:HOME/path expands", () => {
    expect(expand("$env:HOME/.ssh")).toBe(HOME + "/.ssh")
  })

  test("non-home variable unchanged", () => {
    expect(expand("$GOPATH")).toBe("$GOPATH")
  })

  test("plain path unchanged", () => {
    expect(expand("/usr/bin")).toBe("/usr/bin")
  })

  test("relative path unchanged", () => {
    expect(expand("foo/bar")).toBe("foo/bar")
  })

  test("~user not expanded (not current user tilde)", () => {
    expect(expand("~admin")).toBe("~admin")
  })
})

describe("normalize", () => {
  describe("MSYS paths (win32)", () => {
    test("/c/ -> C:/", () => {
      expect(normalize("/c/Users/me", "win32")).toContain("c:")
    })

    test("/C/ -> C:/", () => {
      expect(normalize("/C/Users/me", "win32")).toContain("c:")
    })

    test("/d/projects -> D:/projects", () => {
      const n = normalize("/d/projects", "win32")
      expect(n).toContain("d:")
      expect(n).toContain("projects")
    })

    test("non-msys path unchanged on win32", () => {
      const n = normalize("C:\\Windows", "win32")
      expect(n).toContain("windows")
    })
  })

  describe("Cygwin paths (win32)", () => {
    test("/cygdrive/c/foo -> C:/foo", () => {
      const n = normalize("/cygdrive/c/foo", "win32")
      expect(n).toContain("c:")
      expect(n).toContain("foo")
    })

    test("/cygdrive/D/bar -> D:/bar", () => {
      const n = normalize("/cygdrive/D/bar", "win32")
      expect(n).toContain("d:")
      expect(n).toContain("bar")
    })
  })

  describe("WSL paths (win32)", () => {
    test("/mnt/c/Users -> C:/Users", () => {
      const n = normalize("/mnt/c/Users", "win32")
      expect(n).toContain("c:")
      expect(n).toContain("users")
    })

    test("/mnt/d/projects -> D:/projects", () => {
      const n = normalize("/mnt/d/projects", "win32")
      expect(n).toContain("d:")
      expect(n).toContain("projects")
    })
  })

  describe("non-win32 platforms", () => {
    test("MSYS paths not converted on linux", () => {
      const n = normalize("/c/Users/me", "linux")
      expect(n).toBe("/c/Users/me")
    })

    test("WSL paths not converted on linux", () => {
      const n = normalize("/mnt/c/Users", "linux")
      expect(n).toBe("/mnt/c/Users")
    })
  })

  describe("path.normalize effects", () => {
    test("resolves .. segments", () => {
      const n = normalize("/usr/local/../bin", "linux")
      expect(n).toBe("/usr/bin")
    })

    test("resolves double slashes", () => {
      const n = normalize("/usr//bin", "linux")
      expect(n).toBe("/usr/bin")
    })

    test("strips trailing slash", () => {
      const n = normalize("/usr/bin/", "linux")
      expect(n).toBe("/usr/bin")
    })

    test("preserves root /", () => {
      const n = normalize("/", "linux")
      expect(n).toBe("/")
    })
  })

  describe("case normalization", () => {
    test("lowercase on win32", () => {
      const n = normalize("C:\\Windows\\System32", "win32")
      expect(n).toBe(n.toLowerCase())
    })

    test("lowercase on darwin", () => {
      const n = normalize("/Users/Admin/Documents", "darwin")
      expect(n).toBe("/users/admin/documents")
    })

    test("case preserved on linux", () => {
      const n = normalize("/home/Admin/Documents", "linux")
      expect(n).toBe("/home/Admin/Documents")
    })
  })
})

describe("resolve", () => {
  test("absolute path resolves directly", () => {
    const r = resolve("/usr/bin", "/home/user", "linux")
    expect(r).toBe("/usr/bin")
  })

  test("relative path resolves against cwd", () => {
    const r = resolve("foo/bar", "/home/user", "linux")
    expect(r).toBe("/home/user/foo/bar")
  })

  test("tilde path expands then resolves", () => {
    const r = resolve("~/.ssh", "/home/user", IS_WIN ? "win32" : "linux")
    expect(r).not.toBeNull()
    expect(r!).toContain(".ssh")
  })

  test("$HOME path expands then resolves", () => {
    const r = resolve("$HOME/.aws", "/home/user", IS_WIN ? "win32" : "linux")
    expect(r).not.toBeNull()
    expect(r!).toContain(".aws")
  })

  test("unresolvable variable returns null", () => {
    expect(resolve("$GOPATH/bin", "/home/user", "linux")).toBeNull()
  })

  test("env variable returns null", () => {
    expect(resolve("%APPDATA%\\foo", "C:\\Users\\me", "win32")).toBeNull()
  })

  test(".. in relative path resolves", () => {
    const r = resolve("../../etc", "/home/user/project", "linux")
    expect(r).toBe("/home/etc")
  })

  test("MSYS path on win32 resolves", () => {
    const r = resolve("/c/Windows", "C:\\Users\\me", "win32")
    expect(r).not.toBeNull()
    expect(r!).toContain("c:")
    expect(r!).toContain("windows")
  })
})
