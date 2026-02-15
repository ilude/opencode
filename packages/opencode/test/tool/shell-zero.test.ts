import { describe, expect, test } from "bun:test"
import { zero } from "../../src/tool/shell-zero"
import os from "os"
import path from "path"

const HOME = os.homedir()
const IS_WIN = process.platform === "win32"
const platform = process.platform
const cwd = IS_WIN ? "C:\\Users\\me\\project" : "/home/user/project"
const project = cwd

describe("zero-access exempt commands", () => {
  test("ls on ssh dir is exempt", () => {
    expect(zero(["ls", "~/.ssh/"], cwd, project, platform).decision).toBe("allow")
  })

  test("stat on ssh key is exempt", () => {
    expect(zero(["stat", "~/.ssh/id_rsa"], cwd, project, platform).decision).toBe("allow")
  })

  test("ssh-keygen is exempt", () => {
    expect(zero(["ssh-keygen", "-t", "rsa"], cwd, project, platform).decision).toBe("allow")
  })

  test("ssh-add is exempt", () => {
    expect(zero(["ssh-add", "~/.ssh/id_rsa"], cwd, project, platform).decision).toBe("allow")
  })

  test("git status is exempt", () => {
    expect(zero(["git", "status"], cwd, project, platform).decision).toBe("allow")
  })

  test("git check-ignore is exempt", () => {
    expect(zero(["git", "check-ignore", "~/.ssh/id_rsa"], cwd, project, platform).decision).toBe("allow")
  })

  test("git diff --name-only is exempt", () => {
    expect(zero(["git", "diff", "--name-only"], cwd, project, platform).decision).toBe("allow")
  })

  test("git rm --cached is exempt", () => {
    expect(zero(["git", "rm", "--cached", "file"], cwd, project, platform).decision).toBe("allow")
  })
})

describe("zero-access SSH/GPG paths", () => {
  test("cat ~/.ssh/id_rsa blocks", () => {
    expect(zero(["cat", "~/.ssh/id_rsa"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.ssh/config blocks", () => {
    expect(zero(["cat", "~/.ssh/config"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.gnupg/secring.gpg blocks", () => {
    expect(zero(["cat", "~/.gnupg/secring.gpg"], cwd, project, platform).decision).toBe("block")
  })

  test("absolute path to .ssh blocks", () => {
    const sshPath = path.join(HOME, ".ssh", "id_rsa")
    expect(zero(["cat", sshPath], cwd, project, platform).decision).toBe("block")
  })
})

describe("zero-access cloud credentials", () => {
  test("cat ~/.aws/credentials blocks", () => {
    expect(zero(["cat", "~/.aws/credentials"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.aws/sso/cache/token blocks", () => {
    expect(zero(["cat", "~/.aws/sso/cache/token"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.config/gcloud/credentials blocks", () => {
    expect(zero(["cat", "~/.config/gcloud/credentials"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.azure/accessTokens.json blocks", () => {
    expect(zero(["cat", "~/.azure/accessTokens.json"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.kube/config blocks", () => {
    expect(zero(["cat", "~/.kube/config"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.docker/config.json blocks", () => {
    expect(zero(["cat", "~/.docker/config.json"], cwd, project, platform).decision).toBe("block")
  })
})

describe("zero-access package manager auth", () => {
  test("cat ~/.netrc blocks", () => {
    expect(zero(["cat", "~/.netrc"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.npmrc blocks", () => {
    expect(zero(["cat", "~/.npmrc"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.pypirc blocks", () => {
    expect(zero(["cat", "~/.pypirc"], cwd, project, platform).decision).toBe("block")
  })

  test("cat ~/.git-credentials blocks", () => {
    expect(zero(["cat", "~/.git-credentials"], cwd, project, platform).decision).toBe("block")
  })
})

describe("zero-access glob patterns (outside project)", () => {
  test("*.pem outside project blocks", () => {
    const target = IS_WIN ? "C:\\certs\\server.pem" : "/etc/ssl/server.pem"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })

  test("*.pfx outside project blocks", () => {
    const target = IS_WIN ? "C:\\certs\\cert.pfx" : "/etc/ssl/cert.pfx"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })

  test("*.kdbx outside project blocks", () => {
    const target = IS_WIN ? "C:\\Users\\me\\passwords.kdbx" : "/home/other/passwords.kdbx"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })

  test("dump.sql outside project blocks", () => {
    const target = IS_WIN ? "C:\\backups\\dump.sql" : "/backups/dump.sql"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })

  test("*.tfvars outside project blocks", () => {
    const target = IS_WIN ? "C:\\infra\\prod.tfvars" : "/infra/prod.tfvars"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })

  test(".env outside project blocks", () => {
    const target = IS_WIN ? "C:\\other-project\\.env" : "/other-project/.env"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })

  test("wallet.dat outside project blocks", () => {
    const target = IS_WIN ? "C:\\crypto\\wallet.dat" : "/crypto/wallet.dat"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })
})

describe("zero-access glob patterns (inside project — allowed)", () => {
  test("*.pem inside project is allowed", () => {
    const target = path.join(project, "certs", "server.pem")
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("allow")
  })

  test("dump.sql inside project is allowed", () => {
    const target = path.join(project, "test", "fixtures", "dump.sql")
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("allow")
  })

  test("*.tfvars inside project is allowed", () => {
    const target = path.join(project, "terraform.tfvars")
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("allow")
  })

  test(".env inside project is allowed", () => {
    const target = path.join(project, ".env")
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("allow")
  })
})

describe("zero-access system credentials", () => {
  test("/etc/shadow blocks (linux)", () => {
    expect(zero(["cat", "/etc/shadow"], cwd, project, "linux").decision).toBe("block")
  })

  test("/etc/master.passwd blocks (linux)", () => {
    expect(zero(["cat", "/etc/master.passwd"], cwd, project, "linux").decision).toBe("block")
  })
})

describe("zero-access edge cases", () => {
  test("empty tokens returns allow", () => {
    expect(zero([], cwd, project, platform).decision).toBe("allow")
  })

  test("command with no path args returns allow", () => {
    expect(zero(["echo", "hello"], cwd, project, platform).decision).toBe("allow")
  })

  test("flags are skipped", () => {
    expect(zero(["cat", "-n", "~/.ssh/id_rsa"], cwd, project, platform).decision).toBe("block")
  })

  test("$HOME expansion works for ssh", () => {
    expect(zero(["cat", "$HOME/.ssh/id_rsa"], cwd, project, platform).decision).toBe("block")
  })

  test("unresolvable variable reference is skipped", () => {
    expect(zero(["cat", "$SOME_VAR"], cwd, project, platform).decision).toBe("allow")
  })

  test("terraform dir blocks", () => {
    // .terraform/ relative to cwd — this resolves to cwd/.terraform/
    // which is inside the project, so the dir prefix won't match
    // (dir prefixes expand ~ which .terraform/ doesn't have)
    // The .terraform/ prefix only blocks if the expanded path matches
    // For this to block, it needs to be outside the project
    const target = IS_WIN ? "C:\\other\\.terraform\\state" : "/other/.terraform/state"
    expect(zero(["cat", target], cwd, project, platform).decision).toBe("block")
  })
})
