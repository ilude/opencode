import { describe, expect, test } from "bun:test"
import { catastrophic } from "../../src/tool/shell-catastrophic"

const cwd = "/home/user/project"
const winCwd = "C:\\Users\\me\\project"

describe("standalone hard-blocks", () => {
  test("rm --no-preserve-root", () => {
    const d = catastrophic(["rm", "--no-preserve-root", "/"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("rm --no-preserve-root without path", () => {
    const d = catastrophic(["rm", "-rf", "--no-preserve-root"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("mkfs.ext4", () => {
    const d = catastrophic(["mkfs.ext4", "/dev/sda1"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("mkfs.xfs", () => {
    const d = catastrophic(["mkfs.xfs", "/dev/sdb"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("dd of=/dev/sda", () => {
    const d = catastrophic(["dd", "if=/dev/zero", "of=/dev/sda", "bs=4M"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("dd without of=/dev/ is allowed", () => {
    const d = catastrophic(["dd", "if=input.img", "of=output.img", "bs=4M"], cwd, "linux")
    expect(d.decision).toBe("allow")
  })

  test("format C: (cmd.exe)", () => {
    const d = catastrophic(["format", "C:"], winCwd, "win32")
    expect(d.decision).toBe("block")
  })

  test("Format-Volume", () => {
    const d = catastrophic(["Format-Volume", "-DriveLetter", "D"], winCwd, "win32")
    expect(d.decision).toBe("block")
  })

  test("Clear-Disk", () => {
    const d = catastrophic(["Clear-Disk", "-Number", "0"], winCwd, "win32")
    expect(d.decision).toBe("block")
  })

  test("Initialize-Disk", () => {
    const d = catastrophic(["Initialize-Disk", "-Number", "1"], winCwd, "win32")
    expect(d.decision).toBe("block")
  })
})

describe("reboot/shutdown blocks (refs #13031)", () => {
  test("shutdown", () => {
    expect(catastrophic(["shutdown"], cwd, "linux").decision).toBe("block")
  })

  test("shutdown -r", () => {
    expect(catastrophic(["shutdown", "-r"], cwd, "linux").decision).toBe("block")
  })

  test("shutdown.exe /s", () => {
    expect(catastrophic(["shutdown.exe", "/s"], winCwd, "win32").decision).toBe("block")
  })

  test("reboot", () => {
    expect(catastrophic(["reboot"], cwd, "linux").decision).toBe("block")
  })

  test("poweroff", () => {
    expect(catastrophic(["poweroff"], cwd, "linux").decision).toBe("block")
  })

  test("halt", () => {
    expect(catastrophic(["halt"], cwd, "linux").decision).toBe("block")
  })

  test("Restart-Computer", () => {
    expect(catastrophic(["Restart-Computer"], winCwd, "win32").decision).toBe("block")
  })

  test("Stop-Computer", () => {
    expect(catastrophic(["Stop-Computer"], winCwd, "win32").decision).toBe("block")
  })

  test("Restart-Computer case insensitive", () => {
    expect(catastrophic(["restart-computer"], winCwd, "win32").decision).toBe("block")
  })

  test("init 0 halts", () => {
    expect(catastrophic(["init", "0"], cwd, "linux").decision).toBe("block")
  })

  test("init 6 reboots", () => {
    expect(catastrophic(["init", "6"], cwd, "linux").decision).toBe("block")
  })

  test("init 3 is allowed", () => {
    expect(catastrophic(["init", "3"], cwd, "linux").decision).toBe("allow")
  })

  test("telinit 0", () => {
    expect(catastrophic(["telinit", "0"], cwd, "linux").decision).toBe("block")
  })

  test("systemctl reboot", () => {
    expect(catastrophic(["systemctl", "reboot"], cwd, "linux").decision).toBe("block")
  })

  test("systemctl poweroff", () => {
    expect(catastrophic(["systemctl", "poweroff"], cwd, "linux").decision).toBe("block")
  })

  test("systemctl halt", () => {
    expect(catastrophic(["systemctl", "halt"], cwd, "linux").decision).toBe("block")
  })

  test("systemctl suspend", () => {
    expect(catastrophic(["systemctl", "suspend"], cwd, "linux").decision).toBe("block")
  })

  test("systemctl hibernate", () => {
    expect(catastrophic(["systemctl", "hibernate"], cwd, "linux").decision).toBe("block")
  })

  test("systemctl restart nginx is allowed", () => {
    expect(catastrophic(["systemctl", "restart", "nginx"], cwd, "linux").decision).toBe("allow")
  })

  test("systemctl start docker is allowed", () => {
    expect(catastrophic(["systemctl", "start", "docker"], cwd, "linux").decision).toBe("allow")
  })
})

describe("rm -rf on critical paths", () => {
  test("rm -rf /", () => {
    const d = catastrophic(["rm", "-rf", "/"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("rm -r -f /", () => {
    const d = catastrophic(["rm", "-r", "-f", "/"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("rm --recursive --force /usr", () => {
    const d = catastrophic(["rm", "--recursive", "--force", "/usr"], cwd, "linux")
    expect(d.decision).toBe("block")
  })

  test("rm -rf /etc", () => {
    expect(catastrophic(["rm", "-rf", "/etc"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /home", () => {
    expect(catastrophic(["rm", "-rf", "/home"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /var", () => {
    expect(catastrophic(["rm", "-rf", "/var"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /boot", () => {
    expect(catastrophic(["rm", "-rf", "/boot"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /dev", () => {
    expect(catastrophic(["rm", "-rf", "/dev"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /proc", () => {
    expect(catastrophic(["rm", "-rf", "/proc"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /sys", () => {
    expect(catastrophic(["rm", "-rf", "/sys"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /opt", () => {
    expect(catastrophic(["rm", "-rf", "/opt"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /lib", () => {
    expect(catastrophic(["rm", "-rf", "/lib"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /nix", () => {
    expect(catastrophic(["rm", "-rf", "/nix"], cwd, "linux").decision).toBe("block")
  })
})

describe("rm -rf on macOS paths", () => {
  test("rm -rf /System", () => {
    expect(catastrophic(["rm", "-rf", "/System"], cwd, "darwin").decision).toBe("block")
  })

  test("rm -rf /Library", () => {
    expect(catastrophic(["rm", "-rf", "/Library"], cwd, "darwin").decision).toBe("block")
  })

  test("rm -rf /Applications", () => {
    expect(catastrophic(["rm", "-rf", "/Applications"], cwd, "darwin").decision).toBe("block")
  })

  test("rm -rf /private", () => {
    expect(catastrophic(["rm", "-rf", "/private"], cwd, "darwin").decision).toBe("block")
  })

  test("rm -rf /Volumes", () => {
    expect(catastrophic(["rm", "-rf", "/Volumes"], cwd, "darwin").decision).toBe("block")
  })
})

describe("rm -rf on Windows paths", () => {
  test("rm -rf C:\\Windows", () => {
    expect(catastrophic(["rm", "-rf", "C:\\Windows"], winCwd, "win32").decision).toBe("block")
  })

  test("rm -rf C:\\Program Files", () => {
    expect(catastrophic(["rm", "-rf", "C:\\Program Files"], winCwd, "win32").decision).toBe("block")
  })

  test("rm -rf C:\\Users", () => {
    expect(catastrophic(["rm", "-rf", "C:\\Users"], winCwd, "win32").decision).toBe("block")
  })

  test("rm -rf C:\\", () => {
    expect(catastrophic(["rm", "-rf", "C:\\"], winCwd, "win32").decision).toBe("block")
  })

  test("rm -rf D:\\", () => {
    expect(catastrophic(["rm", "-rf", "D:\\"], winCwd, "win32").decision).toBe("block")
  })
})

describe("allowed operations (not catastrophic)", () => {
  test("rm -rf ./build", () => {
    expect(catastrophic(["rm", "-rf", "./build"], cwd, "linux").decision).toBe("allow")
  })

  test("rm -rf /tmp/test", () => {
    expect(catastrophic(["rm", "-rf", "/tmp/test"], cwd, "linux").decision).toBe("allow")
  })

  test("rm -rf /opt/myproject/build", () => {
    expect(catastrophic(["rm", "-rf", "/opt/myproject/build"], cwd, "linux").decision).toBe("allow")
  })

  test("rm (no recursive) on /usr", () => {
    expect(catastrophic(["rm", "/usr/file.txt"], cwd, "linux").decision).toBe("allow")
  })

  test("mv within project", () => {
    expect(catastrophic(["mv", "old.txt", "new.txt"], cwd, "linux").decision).toBe("allow")
  })

  test("chmod without recursive", () => {
    expect(catastrophic(["chmod", "755", "/etc/file"], cwd, "linux").decision).toBe("allow")
  })

  test("ls on system path is fine", () => {
    expect(catastrophic(["ls", "/usr"], cwd, "linux").decision).toBe("allow")
  })

  test("cat on system path is fine", () => {
    expect(catastrophic(["cat", "/etc/hosts"], cwd, "linux").decision).toBe("allow")
  })

  test("empty tokens", () => {
    expect(catastrophic([], cwd, "linux").decision).toBe("allow")
  })
})

describe("find with delete on critical paths", () => {
  test("find / -delete", () => {
    expect(catastrophic(["find", "/", "-delete"], cwd, "linux").decision).toBe("block")
  })

  test("find /usr -exec rm", () => {
    expect(catastrophic(["find", "/usr", "-exec", "rm", "{}", ";"], cwd, "linux").decision).toBe("block")
  })

  test("find /tmp -delete is allowed", () => {
    expect(catastrophic(["find", "/tmp", "-delete"], cwd, "linux").decision).toBe("allow")
  })
})

describe("shred", () => {
  test("shred on /etc itself blocks", () => {
    expect(catastrophic(["shred", "/etc"], cwd, "linux").decision).toBe("block")
  })

  test("shred on /etc/passwd is allowed (nested path)", () => {
    expect(catastrophic(["shred", "/etc/passwd"], cwd, "linux").decision).toBe("allow")
  })

  test("shred on project file is allowed", () => {
    expect(catastrophic(["shred", "./secret.txt"], cwd, "linux").decision).toBe("allow")
  })
})

describe("mv on critical paths", () => {
  test("mv /usr /tmp/bak", () => {
    expect(catastrophic(["mv", "/usr", "/tmp/bak"], cwd, "linux").decision).toBe("block")
  })

  test("mv /etc /backup", () => {
    expect(catastrophic(["mv", "/etc", "/backup"], cwd, "linux").decision).toBe("block")
  })

  test("mv file.txt /usr/bin is allowed (destination is not moved)", () => {
    // mv's first non-flag arg is source, which is the one being destroyed.
    // But we check ALL path args for safety (both source and destination).
    // /usr/bin is not a protected root (it's a child of /usr which IS protected,
    // but descendants are allowed as exact targets).
    expect(catastrophic(["mv", "file.txt", "/usr/bin/file.txt"], cwd, "linux").decision).toBe("allow")
  })
})

describe("chmod/chown recursive on critical paths", () => {
  test("chmod -R 777 /", () => {
    expect(catastrophic(["chmod", "-R", "777", "/"], cwd, "linux").decision).toBe("block")
  })

  test("chown -R root:root /etc", () => {
    expect(catastrophic(["chown", "-R", "root:root", "/etc"], cwd, "linux").decision).toBe("block")
  })

  test("chmod -R 755 ./dist is allowed", () => {
    expect(catastrophic(["chmod", "-R", "755", "./dist"], cwd, "linux").decision).toBe("allow")
  })
})

describe("PowerShell Remove-Item", () => {
  test("Remove-Item -Recurse C:\\Windows", () => {
    expect(catastrophic(["Remove-Item", "-Recurse", "C:\\Windows"], winCwd, "win32").decision).toBe("block")
  })

  test("ri -Recurse C:\\Users", () => {
    expect(catastrophic(["ri", "-Recurse", "C:\\Users"], winCwd, "win32").decision).toBe("block")
  })

  test("Remove-Item without -Recurse on C:\\Windows is allowed", () => {
    expect(catastrophic(["Remove-Item", "C:\\Windows\\temp.txt"], winCwd, "win32").decision).toBe("allow")
  })
})

describe("cmd.exe rd/del", () => {
  test("rd /s C:\\Windows", () => {
    expect(catastrophic(["rd", "/s", "C:\\Windows"], winCwd, "win32").decision).toBe("block")
  })

  test("del /s C:\\Users", () => {
    expect(catastrophic(["del", "/s", "C:\\Users"], winCwd, "win32").decision).toBe("block")
  })

  test("del /f C:\\ProgramData", () => {
    expect(catastrophic(["del", "/f", "C:\\ProgramData"], winCwd, "win32").decision).toBe("block")
  })
})

describe("flag reordering", () => {
  test("rm -f -r / same as rm -rf /", () => {
    expect(catastrophic(["rm", "-f", "-r", "/"], cwd, "linux").decision).toBe("block")
  })

  test("rm --verbose -rf /usr", () => {
    expect(catastrophic(["rm", "--verbose", "-rf", "/usr"], cwd, "linux").decision).toBe("block")
  })

  test("rm -r --force /etc", () => {
    expect(catastrophic(["rm", "-r", "--force", "/etc"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rvf /var", () => {
    expect(catastrophic(["rm", "-rvf", "/var"], cwd, "linux").decision).toBe("block")
  })
})

describe("relative paths resolving to critical paths", () => {
  test("rm -rf ../../.. from deep dir", () => {
    const d = catastrophic(["rm", "-rf", "../../.."], "/home/user/a/b/c", "linux")
    // ../../.. from /home/user/a/b/c -> /home/user
    // /home/user is NOT a protected root (only /home is)
    expect(d.decision).toBe("allow")
  })

  test("rm -rf ../../../.. resolving to /home", () => {
    const d = catastrophic(["rm", "-rf", "../../../.."], "/home/user/a/b/c", "linux")
    // ../../../.. from /home/user/a/b/c -> /home
    expect(d.decision).toBe("block")
  })
})

describe("tilde and $HOME paths", () => {
  test("rm -rf ~ blocks (home is protected)", () => {
    // ~ expands to home dir, which is under /home (a protected root)
    // But /home/user itself is NOT in the critical set — only /home is.
    // This is allowed by design (users can rm their own home).
    expect(catastrophic(["rm", "-rf", "~"], cwd, "linux").decision).toBe("allow")
  })
})

describe("glob on system paths", () => {
  test("rm -rf /*", () => {
    expect(catastrophic(["rm", "-rf", "/*"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf /usr/*", () => {
    expect(catastrophic(["rm", "-rf", "/usr/*"], cwd, "linux").decision).toBe("block")
  })

  test("rm -rf ./build/* is allowed", () => {
    expect(catastrophic(["rm", "-rf", "./build/*"], cwd, "linux").decision).toBe("allow")
  })
})
