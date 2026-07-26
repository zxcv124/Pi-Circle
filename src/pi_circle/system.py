from __future__ import annotations

from dataclasses import dataclass
import subprocess


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    def run(self, args: list[str], check: bool = True) -> CommandResult:
        completed = subprocess.run(args, check=False, capture_output=True, text=True)
        result = CommandResult(tuple(args), completed.returncode, completed.stdout, completed.stderr)
        if check and completed.returncode != 0:
            joined = " ".join(args)
            raise RuntimeError(f"Command failed ({completed.returncode}): {joined}\n{completed.stderr.strip()}")
        return result

    def popen(self, args: list[str]) -> subprocess.Popen[str]:
        return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
