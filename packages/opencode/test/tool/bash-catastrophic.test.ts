import { describe, expect, test } from "bun:test"
import path from "path"
import { BashTool } from "../../src/tool/bash"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

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

describe("bash catastrophic protection", () => {
  test("blocks rm -rf /", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "rm -rf /", description: "Destroy root" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks rm --no-preserve-root", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "rm -rf --no-preserve-root /tmp", description: "No preserve root" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks shutdown (refs #13031)", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "shutdown -r now", description: "Reboot" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks reboot (refs #13031)", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "reboot", description: "Reboot system" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks Restart-Computer via bash (refs #13031 root cause)", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        // This was the exact root cause of #13031: PowerShell cmdlet
        // submitted to the bash tool bypassed all protections
        await expect(
          bash.execute(
            { command: "Restart-Computer -Force", description: "PowerShell reboot via bash" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks mkfs", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "mkfs.ext4 /dev/sda1", description: "Format disk" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks dd of=/dev/", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "dd if=/dev/zero of=/dev/sda bs=4M", description: "Wipe disk" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks rm -rf on critical system path", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        // Use platform-appropriate critical path
        const target = process.platform === "win32" ? "C:\\Windows" : "/usr"
        await expect(
          bash.execute(
            { command: `rm -rf ${target}`, description: "Remove system dir" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks systemctl reboot", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "systemctl reboot", description: "Systemd reboot" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("allows rm -rf on project file", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        await Bun.write(path.join(dir, "build", "output.txt"), "x")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        // Should not throw — removing project files is fine
        const result = await bash.execute(
          { command: "rm -rf build", description: "Clean build dir" },
          ctx,
        )
        expect(result.metadata.exit).toBeDefined()
      },
    })
  })

  test("allows echo and safe commands", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const result = await bash.execute(
          { command: "echo hello", description: "Echo test" },
          ctx,
        )
        expect(result.metadata.exit).toBe(0)
      },
    })
  })

  test("blocks sudo rm -rf / (unwrapped)", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "sudo rm -rf /", description: "Sudo destroy root" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks command in second position of &&", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const target = process.platform === "win32" ? "C:\\Windows" : "/usr"
        await expect(
          bash.execute(
            { command: `echo foo && rm -rf ${target}`, description: "Chain with rm" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("error message suggests manual terminal", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: "rm -rf /", description: "Destroy" },
            ctx,
          ),
        ).rejects.toThrow("run it manually in your own terminal")
      },
    })
  })
})
