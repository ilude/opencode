import { describe, expect, test } from "bun:test"
import { tokenize, unwrap } from "../../src/tool/shell-unwrap"

describe("tokenize", () => {
  test("simple command", () => {
    expect(tokenize("ls -la")).toEqual([["ls", "-la"]])
  })

  test("double-quoted string", () => {
    expect(tokenize('echo "hello world"')).toEqual([["echo", "hello world"]])
  })

  test("single-quoted string", () => {
    expect(tokenize("echo 'hello world'")).toEqual([["echo", "hello world"]])
  })

  test("escaped characters in double quotes", () => {
    expect(tokenize('echo "say \\"hi\\""')).toEqual([["echo", 'say "hi"']])
  })

  test("combined short flags preserved", () => {
    expect(tokenize("rm -rf /tmp")).toEqual([["rm", "-rf", "/tmp"]])
  })

  test("semicolon splits groups", () => {
    expect(tokenize("echo a ; echo b")).toEqual([
      ["echo", "a"],
      ["echo", "b"],
    ])
  })

  test("&& splits groups", () => {
    expect(tokenize("echo a && echo b")).toEqual([
      ["echo", "a"],
      ["echo", "b"],
    ])
  })

  test("|| splits groups", () => {
    expect(tokenize("echo a || echo b")).toEqual([
      ["echo", "a"],
      ["echo", "b"],
    ])
  })

  test("pipe splits groups", () => {
    expect(tokenize("cat file | grep foo")).toEqual([
      ["cat", "file"],
      ["grep", "foo"],
    ])
  })

  test("mixed operators", () => {
    expect(tokenize("echo a && echo b | grep c ; echo d")).toEqual([
      ["echo", "a"],
      ["echo", "b"],
      ["grep", "c"],
      ["echo", "d"],
    ])
  })

  test("empty input", () => {
    expect(tokenize("")).toEqual([])
  })

  test("whitespace only", () => {
    expect(tokenize("   \t  ")).toEqual([])
  })

  test("escaped space in bare word", () => {
    expect(tokenize("echo hello\\ world")).toEqual([["echo", "hello world"]])
  })

  test("consecutive semicolons skip empty groups", () => {
    expect(tokenize("echo a ;; echo b")).toEqual([
      ["echo", "a"],
      ["echo", "b"],
    ])
  })

  test("path with equals", () => {
    expect(tokenize("dd if=/dev/zero of=/dev/sda")).toEqual([
      ["dd", "if=/dev/zero", "of=/dev/sda"],
    ])
  })
})

describe("unwrap — shell wrappers", () => {
  test("bash -c unwraps", () => {
    const result = unwrap(["bash", "-c", "rm -rf /"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("sh -c unwraps", () => {
    const result = unwrap(["sh", "-c", "echo hello"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["echo", "hello"])
  })

  test("zsh -c unwraps", () => {
    const result = unwrap(["zsh", "-c", "ls -la"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["ls", "-la"])
  })

  test("cmd /c unwraps", () => {
    const result = unwrap(["cmd", "/c", "rd /s /q C:\\data"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toContain("rd")
  })

  test("cmd.exe /k unwraps", () => {
    const result = unwrap(["cmd.exe", "/k", "dir C:\\"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toContain("dir")
  })

  test("pwsh -Command unwraps", () => {
    const result = unwrap(["pwsh", "-Command", "Remove-Item -Recurse ~"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toContain("Remove-Item")
  })

  test("powershell.exe -c unwraps", () => {
    const result = unwrap(["powershell.exe", "-c", "Get-Process"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["Get-Process"])
  })
})

describe("unwrap — wsl", () => {
  test("wsl direct unwraps", () => {
    const result = unwrap(["wsl", "rm", "-rf", "/"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("wsl.exe direct unwraps", () => {
    const result = unwrap(["wsl.exe", "ls", "-la"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["ls", "-la"])
  })
})

describe("unwrap — eval", () => {
  test("eval unwraps remaining tokens", () => {
    const result = unwrap(["eval", "rm -rf /"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("eval with multiple tokens joins and retokenizes", () => {
    const result = unwrap(["eval", "echo", "hello"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["echo", "hello"])
  })
})

describe("unwrap — sudo / doas", () => {
  test("sudo strips and unwraps", () => {
    const result = unwrap(["sudo", "rm", "-rf", "/"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("sudo with -u flag strips flag and value", () => {
    const result = unwrap(["sudo", "-u", "root", "bash", "-c", "reboot"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["reboot"])
  })

  test("sudo with -- separator", () => {
    const result = unwrap(["sudo", "--", "rm", "-rf", "/"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("doas strips and unwraps", () => {
    const result = unwrap(["doas", "rm", "-rf", "/"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("sudo with -E flag", () => {
    const result = unwrap(["sudo", "-E", "make", "install"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["make", "install"])
  })
})

describe("unwrap — runas", () => {
  test("runas /user:Admin strips and unwraps", () => {
    const result = unwrap(["runas", "/user:Administrator", "cmd", "/c", "shutdown /r"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toContain("shutdown")
  })
})

describe("unwrap — xargs", () => {
  test("xargs with command", () => {
    const result = unwrap(["xargs", "rm", "-rf"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf"])
  })

  test("xargs strips flags with values", () => {
    const result = unwrap(["xargs", "-n", "1", "-I", "{}", "rm", "-rf", "{}"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "{}"])
  })

  test("xargs strips -0 flag", () => {
    const result = unwrap(["xargs", "-0", "rm", "-rf"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf"])
  })
})

describe("unwrap — env", () => {
  test("env strips KEY=val pairs", () => {
    const result = unwrap(["env", "FOO=bar", "BAZ=qux", "echo", "hello"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["echo", "hello"])
  })

  test("env with no vars passes through", () => {
    const result = unwrap(["env", "echo", "hello"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["echo", "hello"])
  })
})

describe("unwrap — interpreters", () => {
  test("python -c with os.system extracts inner command", () => {
    const result = unwrap(["python", "-c", "import os; os.system('reboot')"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["reboot"])
  })

  test("python3 -c with subprocess.run extracts inner command", () => {
    const result = unwrap(["python3", "-c", "import subprocess; subprocess.run('ls -la')"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["ls", "-la"])
  })

  test("node -e with execSync extracts inner command", () => {
    const result = unwrap(["node", "-e", "require('child_process').execSync('rm -rf /')"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("ruby -e with system extracts inner command", () => {
    const result = unwrap(["ruby", "-e", "system('ls -la')"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["ls", "-la"])
  })

  test("perl -e with system extracts inner command", () => {
    const result = unwrap(["perl", "-e", "system('whoami')"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["whoami"])
  })

  test("python -c without system call returns raw payload", () => {
    const result = unwrap(["python", "-c", "print('hello')"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toContain("print('hello')")
  })
})

describe("unwrap — recursive", () => {
  test("bash -c wrapping bash -c unwraps recursively", () => {
    const result = unwrap(["bash", "-c", "bash -c 'rm -rf /'"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("sudo wrapping bash -c unwraps recursively", () => {
    const result = unwrap(["sudo", "bash", "-c", "rm -rf /"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("env wrapping sudo wrapping rm", () => {
    const result = unwrap(["env", "PATH=/usr/bin", "sudo", "rm", "-rf", "/"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })

  test("depth limit prevents infinite loop", () => {
    const result = unwrap(["bash", "-c", "bash -c 'bash -c \"bash -c \\\"bash -c echo\\\"\"'"], 3)
    expect(result.unwrapped).toBe(true)
    // Should stop after 3 layers regardless
  })

  test("xargs bash -c unwraps both layers", () => {
    const result = unwrap(["xargs", "bash", "-c", "rm -rf /"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["rm", "-rf", "/"])
  })
})

describe("unwrap — no-op cases", () => {
  test("normal command passes through", () => {
    const result = unwrap(["ls", "-la"])
    expect(result.unwrapped).toBe(false)
    expect(result.tokens).toEqual(["ls", "-la"])
  })

  test("empty tokens passes through", () => {
    const result = unwrap([])
    expect(result.unwrapped).toBe(false)
    expect(result.tokens).toEqual([])
  })

  test("bash without -c flag passes through", () => {
    const result = unwrap(["bash", "--version"])
    expect(result.unwrapped).toBe(false)
    expect(result.tokens).toEqual(["bash", "--version"])
  })

  test("python without -c flag passes through", () => {
    const result = unwrap(["python", "script.py"])
    expect(result.unwrapped).toBe(false)
    expect(result.tokens).toEqual(["python", "script.py"])
  })

  test("cmd without /c or /k passes through", () => {
    const result = unwrap(["cmd"])
    expect(result.unwrapped).toBe(false)
    expect(result.tokens).toEqual(["cmd"])
  })
})

describe("unwrap — case insensitivity", () => {
  test("BASH -c unwraps", () => {
    const result = unwrap(["BASH", "-c", "echo hi"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["echo", "hi"])
  })

  test("CMD /C unwraps", () => {
    const result = unwrap(["CMD", "/C", "dir"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["dir"])
  })

  test("Pwsh.exe -Command unwraps", () => {
    const result = unwrap(["Pwsh.exe", "-Command", "Get-Process"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["Get-Process"])
  })

  test("SUDO unwraps", () => {
    const result = unwrap(["SUDO", "ls"])
    expect(result.unwrapped).toBe(true)
    expect(result.tokens).toEqual(["ls"])
  })
})
