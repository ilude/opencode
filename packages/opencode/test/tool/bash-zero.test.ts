import { describe, expect, test } from "bun:test"
import path from "path"
import os from "os"
import { BashTool } from "../../src/tool/bash"
import { Instance } from "../../src/project/instance"
import { tmpdir } from "../fixture/fixture"

const HOME = os.homedir()

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

describe("bash zero-access protection", () => {
  test("blocks cat ~/.ssh/id_rsa", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: `cat ${path.join(HOME, ".ssh", "id_rsa")}`, description: "Read SSH key" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks cat ~/.aws/credentials", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: `cat ${path.join(HOME, ".aws", "credentials")}`, description: "Read AWS creds" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("blocks reading .pem file outside project (refs #12196)", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const target = process.platform === "win32"
          ? "C:\\certs\\server.pem"
          : "/etc/ssl/server.pem"
        await expect(
          bash.execute(
            { command: `cat ${target}`, description: "Read PEM file" },
            ctx,
          ),
        ).rejects.toThrow("Command blocked")
      },
    })
  })

  test("allows reading project files", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        await Bun.write(path.join(dir, "readme.txt"), "hello")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const result = await bash.execute(
          { command: "cat readme.txt", description: "Read project file" },
          ctx,
        )
        expect(result.metadata.exit).toBe(0)
      },
    })
  })

  test("allows .env inside project", async () => {
    await using tmp = await tmpdir({
      git: true,
      init: async (dir) => {
        await Bun.write(path.join(dir, ".env"), "FOO=bar")
      },
    })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        const result = await bash.execute(
          { command: "cat .env", description: "Read project env" },
          ctx,
        )
        expect(result.metadata.exit).toBe(0)
      },
    })
  })

  test("error message includes credential path reason", async () => {
    await using tmp = await tmpdir({ git: true })
    await Instance.provide({
      directory: tmp.path,
      fn: async () => {
        const bash = await BashTool.init()
        await expect(
          bash.execute(
            { command: `cat ${path.join(HOME, ".ssh", "id_rsa")}`, description: "Read key" },
            ctx,
          ),
        ).rejects.toThrow("credential path")
      },
    })
  })
})
