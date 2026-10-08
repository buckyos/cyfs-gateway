import subprocess


def ensure_cargo_lockfile(workspace, env):
    if not (workspace / "Cargo.lock").is_file():
        print("Generating missing Cargo.lock", flush=True)
        subprocess.run(
            ["cargo", "generate-lockfile"],
            cwd=workspace, env=env, check=True,
        )
