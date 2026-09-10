import { describe, it, expect } from "vitest";
import { hasDenySignalInBlock, isGuardPatternContext } from "../../src/rules/guard-context.js";

function at(content: string, needle: string, occurrence = 0): number {
  let index = -1;
  for (let i = 0; i <= occurrence; i++) {
    index = content.indexOf(needle, index + 1);
    if (index === -1) throw new Error(`needle not found: ${needle}`);
  }
  return index;
}

describe("isGuardPatternContext", () => {
  describe("shell matching commands", () => {
    it("detects a quoted grep pattern", () => {
      const content = "printf '%s' \"$CMD\" | grep -qE '(^|\\s)(mkfs|wipefs)(\\s|$)'; echo done";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "wipefs"))).toBe(true);
    });

    it("detects grep with multiple -e patterns and rg/ag", () => {
      const grep = "grep -q -e 'sudo' -e 'crontab' <<< \"$CMD\"";
      expect(isGuardPatternContext(grep, at(grep, "crontab"))).toBe(true);
      const rg = "rg -q 'rm -rf' <<< \"$CMD\"";
      expect(isGuardPatternContext(rg, at(rg, "rm -rf"))).toBe(true);
      const ag = 'ag "iptables" file.txt';
      expect(isGuardPatternContext(ag, at(ag, "iptables"))).toBe(true);
    });

    it("detects awk regex patterns and sed match-only forms", () => {
      const awk = "awk '/mkfs/ { exit 1 }' <<< \"$CMD\"";
      expect(isGuardPatternContext(awk, at(awk, "mkfs"))).toBe(true);
      const sedDelete = "sed '/wipefs/d' file";
      expect(isGuardPatternContext(sedDelete, at(sedDelete, "wipefs"))).toBe(true);
      const sedPrint = "sed -n '/mkfs/p' file";
      expect(isGuardPatternContext(sedPrint, at(sedPrint, "mkfs"))).toBe(true);
      const sedSubstitute = "sed 's/mkfs/format/' file";
      expect(isGuardPatternContext(sedSubstitute, at(sedSubstitute, "mkfs"))).toBe(false);
    });

    it("detects jq select/test filters", () => {
      const content = "jq -e 'select(.tool_input.command | test(\"mkfs\"))' <<< \"$INPUT\"";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(true);
      const plain = "jq -r '.tool_input.command' | grep foo; echo \"mkfs\"";
      expect(isGuardPatternContext(plain, at(plain, "mkfs"))).toBe(false);
    });

    it("detects [[ ]] and [ ] comparisons, quoted or not", () => {
      const regex = "if [[ $CMD =~ mkfs ]]; then";
      expect(isGuardPatternContext(regex, at(regex, "mkfs"))).toBe(true);
      const glob = 'if [[ "$CMD" == *"rm -rf"* ]]; then';
      expect(isGuardPatternContext(glob, at(glob, "rm -rf"))).toBe(true);
      const single = '[ "$TOOL" = "crontab" ] && exit 2';
      expect(isGuardPatternContext(single, at(single, "crontab"))).toBe(true);
    });

    it("does not treat a command after a closed test as a guard", () => {
      const content = '[[ -n "$X" ]] && mkfs /dev/sda';
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("detects case pattern lines inside an open case block", () => {
      const content = 'case "$CMD" in\n  *mkfs*|*"dd if=/dev/zero"*)\n    exit 2 ;;\n  wipe) mkfs.ext4 /dev/sda ;;\nesac\nmkfs /dev/sdb';
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "dd if="))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "mkfs.ext4"))).toBe(false);
      expect(isGuardPatternContext(content, at(content, "mkfs /dev/sdb"))).toBe(false);
    });

    it("detects an inline case pattern", () => {
      const content = 'case "$CMD" in *wipefs*) exit 2 ;; esac';
      expect(isGuardPatternContext(content, at(content, "wipefs"))).toBe(true);
    });
  });

  describe("fail-closed counter examples", () => {
    it("keeps an invocation after a grep on the same line", () => {
      const content = "grep -q x file && mkfs /dev/sda";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("keeps a quoted string piped to a shell", () => {
      const content = 'echo "mkfs /dev/sda" | sh';
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
      const bash = "echo 'rm -rf /' | sudo bash";
      expect(isGuardPatternContext(bash, at(bash, "rm -rf"))).toBe(false);
    });

    it("keeps a quoted string that is eval'd", () => {
      const content = 'eval "mkfs /dev/sda"';
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
      const indirect = 'cmd="mkfs /dev/sda"\neval "$cmd"';
      expect(isGuardPatternContext(indirect, at(indirect, "mkfs"))).toBe(false);
    });

    it("keeps a grep whose result feeds a shell", () => {
      const content = "grep 'mkfs' cmds.txt | bash";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("keeps command substitution inside quotes", () => {
      const content = 'out="$(mkfs /dev/sda)"';
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
      const backtick = "out=\"`wipefs -a /dev/sdb`\"";
      expect(isGuardPatternContext(backtick, at(backtick, "wipefs"))).toBe(false);
    });

    it("keeps an unquoted plain invocation", () => {
      const content = "mkfs.ext4 /dev/sda1";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("keeps an echoed string with no matching command or deny wording", () => {
      const content = "echo 'run mkfs now'";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("treats an echoed deny message that names the token as a guard", () => {
      const json = "echo '{\"decision\":\"deny\",\"reason\":\"Blocked: mkfs\"}'";
      expect(isGuardPatternContext(json, at(json, "mkfs"))).toBe(true);
      const plain = 'echo "Blocked: rm -rf is not allowed" >&2';
      expect(isGuardPatternContext(plain, at(plain, "rm -rf"))).toBe(true);
      const piped = "echo 'Blocked: mkfs /dev/sda' | sh";
      expect(isGuardPatternContext(piped, at(piped, "mkfs"))).toBe(false);
    });

    it("keeps a quote that never closes on the line", () => {
      const content = "grep -q 'mkfs\nfoo' file";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("ignores comment lines and out-of-range indexes", () => {
      const content = "# grep -q 'mkfs'";
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
      expect(isGuardPatternContext(content, -1)).toBe(false);
      expect(isGuardPatternContext(content, content.length + 5)).toBe(false);
    });
  });

  describe("python and javascript checks", () => {
    it("detects python re.* and membership checks", () => {
      const content = [
        'if re.search(r"mkfs", cmd):',
        "    sys.exit(2)",
        'if "rm -rf" in cmd:',
        "    sys.exit(2)",
        'if any(tok in cmd for tok in ("wipefs", "dd if=/dev/zero")):',
        "    sys.exit(2)",
        'subprocess.run("crontab -l")',
      ].join("\n");
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "rm -rf"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "wipefs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "dd if="))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "crontab"))).toBe(false);
    });

    it("detects javascript regex and string checks", () => {
      const content = [
        "if (/mkfs/.test(cmd)) process.exit(2);",
        'if (cmd.includes("rm -rf")) process.exit(2);',
        'if (new RegExp("wipefs").test(cmd)) process.exit(2);',
        'if (cmd.match(/crontab/)) process.exit(2);',
        'execSync("sudo reboot");',
      ].join("\n");
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "rm -rf"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "wipefs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "crontab"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "sudo"))).toBe(false);
    });

    it("detects single-line deny list literals", () => {
      const content = 'const BLOCKED = ["rm -rf", "mkfs"];\nconst RUN = ["wipefs"];';
      expect(isGuardPatternContext(content, at(content, "rm -rf"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "wipefs"))).toBe(false);
    });
  });

  describe("json deny lists", () => {
    it("detects strings under deny/block keys", () => {
      const content = JSON.stringify(
        { permissions: { deny: ["Bash(rm -rf *)"] }, blocked: ["mkfs"], run: ["wipefs"] },
        null,
        2
      );
      expect(isGuardPatternContext(content, at(content, "rm -rf"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "wipefs"))).toBe(false);
    });

    it("detects neutral list keys nested under a deny key", () => {
      const content = JSON.stringify({ deny: { commands: ["crontab"], reason: "no" }, allow: { commands: ["sudo"] } });
      expect(isGuardPatternContext(content, at(content, "crontab"))).toBe(true);
      expect(isGuardPatternContext(content, at(content, "sudo"))).toBe(false);
    });

    it("treats patterns keys as deny lists only for hook configs", () => {
      const content = JSON.stringify({ patterns: ["mkfs"] });
      expect(isGuardPatternContext(content, at(content, "mkfs"), { isHookConfig: true })).toBe(true);
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("does not treat hook commands under a deny-named object as guards when the key is unrelated", () => {
      const content = JSON.stringify({ blocked: { onMatch: { command: "mkfs /dev/sda" } } });
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });

    it("ignores invalid JSON", () => {
      const content = '{"deny": ["mkfs"';
      expect(isGuardPatternContext(content, at(content, "mkfs"))).toBe(false);
    });
  });
});

describe("hasDenySignalInBlock", () => {
  it("finds a deny decision within the enclosing block", () => {
    const content = "if grep -q 'mkfs' <<< \"$CMD\"; then\n  echo '{\"decision\":\"deny\"}'\n  exit 0\nfi";
    expect(hasDenySignalInBlock(content, at(content, "mkfs"))).toBe(true);
  });

  it("finds exit 2, return 1, process.exit(2), sys.exit(2), and Blocked echoes", () => {
    for (const signal of ["exit 2", "exit 1", "return 1", "process.exit(2)", "sys.exit(2)", "echo 'Blocked: nope' >&2", '{"permissionDecision":"deny"}']) {
      const content = `check mkfs\n  ${signal}\nfi`;
      expect(hasDenySignalInBlock(content, at(content, "mkfs"))).toBe(true);
    }
  });

  it("stops at the block terminator", () => {
    const content = "if grep -q 'mkfs' <<< \"$CMD\"; then\n  echo saw\nfi\nexit 2";
    expect(hasDenySignalInBlock(content, at(content, "mkfs"))).toBe(false);
  });

  it("stops at a blank line", () => {
    const content = "grep -q 'mkfs' <<< \"$CMD\"\n\nexit 2";
    expect(hasDenySignalInBlock(content, at(content, "mkfs"))).toBe(false);
  });

  it("respects the line cap", () => {
    const content = ["grep -q 'mkfs'", ...Array.from({ length: 15 }, () => "  echo more"), "  exit 2", "fi"].join("\n");
    expect(hasDenySignalInBlock(content, at(content, "mkfs"))).toBe(false);
    expect(hasDenySignalInBlock(content, at(content, "mkfs"), 20)).toBe(true);
  });

  it("returns false for out-of-range indexes", () => {
    expect(hasDenySignalInBlock("exit 2", -1)).toBe(false);
    expect(hasDenySignalInBlock("exit 2", 50)).toBe(false);
  });
});
