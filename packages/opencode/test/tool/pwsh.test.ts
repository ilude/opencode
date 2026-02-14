import { describe, expect, test } from "bun:test"
import os from "os"
import path from "path"
import { PwshTool } from "../../src/tool/pwsh"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"
import type { PermissionNext } from "../../src/permission/next"
import { Truncate } from "../../src/tool/truncation"

// Helper to access truncation metadata added by the framework at runtime
function truncationMeta(result: { metadata: Record<string, unknown> }) {
  return result.metadata as { truncated: boolean; outputPath?: string }
}

const ctx = {
  sessionID: "test",
  messageID: "",
  callID: "",
  agent: "build",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => {},
  ask: async () => {},
}

const pwsh = Bun.which("pwsh")
const run = pwsh ? describe : describe.skip

run("tool.pwsh", () => {
  test("basic", async () => {
    // Allow 30s for tree-sitter WASM initialization on first test run
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const result = await pwshTool.execute(
          {
            command: "Write-Output 'test'",
            description: "Write test message",
          },
          ctx,
        )
        expect(result.metadata.exit).toBe(0)
        expect(result.metadata.output).toContain("test")
      },
    })
  }, 30_000)
})

run("tool.pwsh permissions", () => {
  test("asks for pwsh permission with correct pattern", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Write-Output hello",
            description: "Write hello",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        expect(requests[0].patterns).toContain("Write-Output hello")
      },
    })
  })

  test("asks for pwsh permission with multiple commands", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Write-Output foo; Write-Output bar",
            description: "Write twice",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        expect(requests[0].patterns).toContain("Write-Output foo")
        expect(requests[0].patterns).toContain("Write-Output bar")
      },
    })
  })

  test("asks for external_directory when Set-Location to parent", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Set-Location ../",
            description: "Change to parent directory",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
      },
    })
  })

  test("asks for external_directory when workdir is outside project", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Get-ChildItem",
            workdir: "/tmp",
            description: "List /tmp",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
        // Pattern may use backslash or forward slash depending on platform
        expect(extDirReq!.patterns.some((p) => p.includes("tmp") && p.includes("*"))).toBe(true)
      },
    })
  })

  test("asks for external_directory when -Path arg is outside project", async () => {
    await using outerTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "outside.txt"), "x")
      },
    })
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        const filepath = path.join(outerTmp.path, "outside.txt")
        await pwshTool.execute(
          {
            command: `Get-Content -Path "${filepath}"`,
            description: "Read external file",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        const expected = path.join(outerTmp.path, "*")
        expect(extDirReq).toBeDefined()
        expect(extDirReq!.patterns).toContain(expected)
        expect(extDirReq!.always).toContain(expected)
      },
    })
  })

  test("does not ask for external_directory when Remove-Item inside project", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }

        await Bun.write(path.join(tmp.path, "tmpfile"), "x")

        await pwshTool.execute(
          {
            command: "Remove-Item tmpfile",
            description: "Remove tmpfile",
          },
          testCtx,
        )

        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeUndefined()
      },
    })
  })

  test("includes always patterns for auto-approval", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "git log --oneline -5",
            description: "Git log",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].always.length).toBeGreaterThan(0)
        expect(requests[0].always.some((p) => p.endsWith("*"))).toBe(true)
      },
    })
  })

  test("does not ask for pwsh permission when command is Set-Location only", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Set-Location .",
            description: "Stay in current directory",
          },
          testCtx,
        )
        const pwshReq = requests.find((r) => r.permission === "pwsh")
        expect(pwshReq).toBeUndefined()
      },
    })
  })

  test("matches redirections in permission pattern", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Get-ChildItem > /tmp/output.txt",
            description: "Redirect output",
          },
          testCtx,
        )
        const pwshReq = requests.find((r) => r.permission === "pwsh")
        expect(pwshReq).toBeDefined()
        expect(pwshReq!.patterns).toContain("Get-ChildItem > /tmp/output.txt")
      },
    })
  })

  test("asks external_directory for nonexistent parent-outside path", async () => {
    await using outerTmp = await tmpdir()
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        const nonexistentPath = path.join(outerTmp.path, "nonexistent", "nested", "file.txt")
        await pwshTool.execute(
          {
            command: `New-Item -Path "${nonexistentPath}" -Force`,
            description: "Create file in nonexistent path",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
        // Should use nearest existing ancestor
        expect(extDirReq!.patterns.some((p) => p.includes(outerTmp.path))).toBe(true)
      },
    })
  })

  test("blocks mixed-path bypass attempts", async () => {
    // Windows only test
    if (process.platform !== "win32") {
      return
    }

    await using outerTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "target.txt"), "x")
      },
    })
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()

        // Test with Windows-style path
        const requests1: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx1 = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests1.push(req)
          },
        }
        const windowsPath = path.join(outerTmp.path, "target.txt")
        await pwshTool.execute(
          {
            command: `Get-Content -Path "${windowsPath}"`,
            description: "Read with Windows path",
          },
          testCtx1,
        )

        // Test with MSYS-style path
        const requests2: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx2 = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests2.push(req)
          },
        }
        const msysPath = windowsPath.replace(/^([A-Z]):/i, (_, drive) => `/${drive.toLowerCase()}`)
        await pwshTool.execute(
          {
            command: `Get-Content -Path "${msysPath}"`,
            description: "Read with MSYS path",
          },
          testCtx2,
        )

        // Both should trigger external_directory
        const extDir1 = requests1.find((r) => r.permission === "external_directory")
        const extDir2 = requests2.find((r) => r.permission === "external_directory")
        expect(extDir1).toBeDefined()
        expect(extDir2).toBeDefined()
      },
    })
  })

  test("MSYS paths do not produce root-wide external_directory patterns", async () => {
    if (process.platform !== "win32") return

    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        // Use MSYS-style path to a specific directory
        await pwshTool.execute(
          {
            command: "Set-Location /c/Users",
            description: "cd via MSYS path",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        if (extDirReq) {
          // Should NOT produce a pattern like "C:\*" (root-wide)
          for (const pattern of extDirReq.patterns) {
            const normalized = pattern.replace(/\\/g, "/")
            expect(normalized).not.toMatch(/^[A-Z]:\/\*$/)
          }
        }
      },
    })
  })

  test("does not crash on invalid workdir", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        try {
          const result = await pwshTool.execute(
            {
              command: "Write-Output test",
              workdir: "/nonexistent/path/that/definitely/does/not/exist",
              description: "Test with invalid workdir",
            },
            ctx,
          )
          // Should not throw, should return result (possibly with error output)
          expect(result).toBeDefined()
          expect(result.metadata).toBeDefined()
        } catch (error) {
          // May throw ENOENT - verify it's a controlled error, not a crash
          expect(error).toHaveProperty("code", "ENOENT")
        }
      },
    })
  })

  test("parser fallback still asks permission and executes", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        // Use a .NET static method call — valid PowerShell but produces no command nodes in tree-sitter
        const staticMethodCall = "[System.Math]::Sqrt(144)"
        await pwshTool.execute(
          {
            command: staticMethodCall,
            description: "Static method call",
          },
          testCtx,
        )
        // Should still ask for pwsh permission with raw pattern
        const pwshReq = requests.find((r) => r.permission === "pwsh")
        expect(pwshReq).toBeDefined()
        expect(pwshReq!.patterns).toContain(staticMethodCall)
      },
    })
  })

  test("handles path parameter forms", async () => {
    await using outerTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "test1.txt"), "x")
        await Bun.write(path.join(dir, "test2.txt"), "x")
        await Bun.write(path.join(dir, "test3.txt"), "x")
      },
    })
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()

        // Test -Path value
        const requests1: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        await pwshTool.execute(
          {
            command: `Get-Content -Path "${path.join(outerTmp.path, "test1.txt")}"`,
            description: "Test -Path value",
          },
          {
            ...ctx,
            ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
              requests1.push(req)
            },
          },
        )

        // Test -Path:value
        const requests2: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        await pwshTool.execute(
          {
            command: `Get-Content -Path:"${path.join(outerTmp.path, "test2.txt")}"`,
            description: "Test -Path:value",
          },
          {
            ...ctx,
            ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
              requests2.push(req)
            },
          },
        )

        // Test -LiteralPath
        const requests3: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        await pwshTool.execute(
          {
            command: `Get-Content -LiteralPath "${path.join(outerTmp.path, "test3.txt")}"`,
            description: "Test -LiteralPath",
          },
          {
            ...ctx,
            ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
              requests3.push(req)
            },
          },
        )

        // All should trigger external_directory
        expect(requests1.find((r) => r.permission === "external_directory")).toBeDefined()
        expect(requests2.find((r) => r.permission === "external_directory")).toBeDefined()
        expect(requests3.find((r) => r.permission === "external_directory")).toBeDefined()
      },
    })
  })

  test("unresolved variable path remains safe", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        // Use variable path that cannot be resolved statically
        await pwshTool.execute(
          {
            command: 'Get-Content -Path "$env:TEMP/test.txt"',
            description: "Read from env var path",
          },
          testCtx,
        )
        // Should still ask for pwsh permission
        const pwshReq = requests.find((r) => r.permission === "pwsh")
        expect(pwshReq).toBeDefined()
        // Should not assume it's in-project
      },
    })
  })

  test("~ path triggers external_directory", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Get-ChildItem ~",
            description: "List home directory",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
        expect(extDirReq!.patterns.some((p) => p.includes(os.homedir()))).toBe(true)
      },
    })
  })

  test("Set-Location ~ triggers external_directory", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Set-Location ~",
            description: "cd to home",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
      },
    })
  })

  test("expanded cmdlets trigger external_directory for outside paths", async () => {
    await using outerTmp = await tmpdir({
      init: async (dir) => {
        await Bun.write(path.join(dir, "target.txt"), "x")
      },
    })
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        const filepath = path.join(outerTmp.path, "target.txt")
        await pwshTool.execute(
          {
            command: `Add-Content -Path "${filepath}" -Value "test"`,
            description: "Append to external file",
          },
          testCtx,
        )
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
        expect(extDirReq!.patterns.some((p) => p.includes(outerTmp.path))).toBe(true)
      },
    })
  })
})

run("tool.pwsh truncation", () => {
  test("truncates output exceeding line limit", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const lineCount = Truncate.MAX_LINES + 500
        const result = await pwshTool.execute(
          {
            command: `1..${lineCount} | ForEach-Object { Write-Output $_ }`,
            description: "Generate lines exceeding limit",
          },
          ctx,
        )
        expect(truncationMeta(result).truncated).toBe(true)
        expect(result.output).toContain("truncated")
        expect(result.output).toContain("The tool call succeeded but the output was truncated")
      },
    })
  })

  test("truncates output exceeding byte limit", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const byteCount = Truncate.MAX_BYTES + 10000
        const result = await pwshTool.execute(
          {
            command: `Write-Output ('a' * ${byteCount})`,
            description: "Generate bytes exceeding limit",
          },
          ctx,
        )
        expect(truncationMeta(result).truncated).toBe(true)
        expect(result.output).toContain("truncated")
        expect(result.output).toContain("The tool call succeeded but the output was truncated")
      },
    })
  })

  test("does not truncate small output", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const result = await pwshTool.execute(
          {
            command: "Write-Output hello",
            description: "Write hello",
          },
          ctx,
        )
        expect(truncationMeta(result).truncated).toBe(false)
        expect(result.output).toContain("hello")
      },
    })
  })

  test("full output saved to file when truncated", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const lineCount = Truncate.MAX_LINES + 100
        const result = await pwshTool.execute(
          {
            command: `1..${lineCount} | ForEach-Object { Write-Output $_ }`,
            description: "Generate lines for file check",
          },
          ctx,
        )
        expect(truncationMeta(result).truncated).toBe(true)

        const filepath = truncationMeta(result).outputPath
        expect(filepath).toBeTruthy()

        const saved = await Bun.file(filepath!).text()
        const lines = saved.trim().split(/\r?\n/)
        expect(lines.length).toBe(lineCount)
        expect(lines[0].trim()).toBe("1")
        expect(lines[lineCount - 1].trim()).toBe(String(lineCount))
      },
    })
  })
})

run("tool.pwsh security", () => {
  test("blocks PowerShell provider path (Cert:\\)", async () => {
    if (process.platform !== "win32") return // Provider paths are Windows-specific
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Get-ChildItem Cert:\\CurrentUser",
            description: "List certificates",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        // Provider path should NOT trigger external_directory (it's not a filesystem path)
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeUndefined()
      },
    })
  }, 15000)

  test("blocks PowerShell provider path (HKCU:\\)", async () => {
    if (process.platform !== "win32") return // Provider paths are Windows-specific
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Get-Item HKCU:\\Software",
            description: "Access registry",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        // Provider path should NOT trigger external_directory
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeUndefined()
      },
    })
  }, 15000)

  test("blocks $HOME path expansion bypass", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Test-Path $HOME",
            description: "Test home directory path",
          },
          testCtx,
        )
        // Should trigger external_directory for home directory access
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
        expect(extDirReq!.patterns.some((p) => p.includes(os.homedir()))).toBe(true)
      },
    })
  }, 15000)

  test("blocks ~ path traversal bypass", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Get-Content ~/../../tmp",
            description: "Attempt traversal via tilde",
          },
          testCtx,
        )
        // Should trigger external_directory
        const extDirReq = requests.find((r) => r.permission === "external_directory")
        expect(extDirReq).toBeDefined()
        // Pattern should NOT be root-wide (like C:\\* on Windows)
        if (process.platform === "win32") {
          const hasRootWildcard = extDirReq!.patterns.some((p) => /^[A-Z]:\\?\*$/i.test(p))
          expect(hasRootWildcard).toBe(false)
        }
      },
    })
  }, 15000)

  test("dangerous cmdlets not auto-approved", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Invoke-Expression 'Write-Output test'",
            description: "Test dangerous cmdlet",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        // Should have pattern but NO auto-approval (empty always array)
        expect(requests[0].patterns.length).toBeGreaterThan(0)
        expect(requests[0].always.length).toBe(0)
      },
    })
  })

  test("dangerous cmdlet aliases not auto-approved (iex)", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "iex 'Get-ChildItem'",
            description: "Test dangerous alias",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        // Should NOT have auto-approval
        expect(requests[0].always.length).toBe(0)
      },
    })
  })

  test("network cmdlets not auto-approved (Invoke-WebRequest)", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Invoke-WebRequest https://example.com",
            description: "Test network cmdlet",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        // Should NOT have auto-approval
        expect(requests[0].always.length).toBe(0)
      },
    })
  })

  test("registry cmdlets not auto-approved (Get-ItemProperty)", async () => {
    if (process.platform !== "win32") return // Registry is Windows-specific
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const pwshTool = await PwshTool.init()
        const requests: Array<Omit<PermissionNext.Request, "id" | "sessionID" | "tool">> = []
        const testCtx = {
          ...ctx,
          ask: async (req: Omit<PermissionNext.Request, "id" | "sessionID" | "tool">) => {
            requests.push(req)
          },
        }
        await pwshTool.execute(
          {
            command: "Get-ItemProperty HKCU:\\Software\\Test",
            description: "Test registry cmdlet",
          },
          testCtx,
        )
        expect(requests.length).toBe(1)
        expect(requests[0].permission).toBe("pwsh")
        // Should NOT have auto-approval
        expect(requests[0].always.length).toBe(0)
      },
    })
  })
})
