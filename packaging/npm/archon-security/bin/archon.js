#!/usr/bin/env node
/**
 * archon-security npm shim.
 *
 * Forwards every argument to the real Python `archon` CLI, installing it on
 * first use via uv (preferred) or pipx. No Node-side logic beyond routing —
 * all security functionality lives in the Python package.
 */
const { spawnSync } = require("child_process");
const path = require("path");

function firstAvailable(cmds) {
  for (const c of cmds) {
    const probe = spawnSync(c, ["--version"], { encoding: "utf8" });
    if (probe.status === 0) return c;
  }
  return null;
}

function main() {
  const args = process.argv.slice(2);
  const runner = firstAvailable(["uv", "pipx"]);

  if (!runner) {
    console.error(
      "archon-security requires 'uv' (https://docs.astral.sh/uv/) or 'pipx' (pip install pipx).\n" +
        "Install one, then re-run: npx archon-security " +
        args.join(" ")
    );
    process.exit(2);
  }

  const repoSpec = "git+https://github.com/Yasirrazaa/archon";
  const cmd =
    runner === "uv"
      ? ["tool", "run", "--from", repoSpec, "archon", ...args]
      : ["run", "--spec", repoSpec, "archon", ...args];

  const result = spawnSync(runner, cmd, { stdio: "inherit" });
  process.exit(result.status ?? 1);
}

if (require.main === module && path.basename(process.argv[1]) !== "npm") {
  main();
}
