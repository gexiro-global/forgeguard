import json
import os
import tempfile
from pathlib import Path

from .exporters.json import render_json
from .exporters.markdown import render_markdown
from .exporters.sarif import to_sarif


def prepare_outputs(fmt: str, out: Path | None, input_path: Path | None = None):
    formats = [s.strip() for s in fmt.split(",")]
    if (
        not formats
        or len(set(formats)) != len(formats)
        or not set(formats) <= {"md", "json", "sarif"}
    ):
        raise ValueError("Unknown or repeated format; choose md,json,sarif")
    if len(formats) > 1 and out is None:
        raise ValueError("Multiple formats require --out")
    paths = {}
    for f in formats:
        path = None if out is None else out if f == "md" else out.with_suffix("." + f)
        if path:
            if any(p.is_symlink() for p in (path, *path.parents)):
                raise ValueError("Output path may not contain symlinks")
            if not path.parent.is_dir():
                raise ValueError("Output directory must already exist")
            if path.exists():
                raise ValueError("Output already exists; choose a new filename")
            if input_path and path.resolve() == input_path.resolve():
                raise ValueError("Output cannot overwrite snapshot input")
        paths[f] = path
    resolved = [str(p.resolve()).casefold() for p in paths.values() if p is not None]
    if len(resolved) != len(set(resolved)):
        raise ValueError("Output paths resolve to the same file")
    return paths


def write_atomic(path: Path, text: str):
    fd, tmp = tempfile.mkstemp(prefix=".forgeguard-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic no-clobber installation, including concurrent writers.
        os.link(tmp, path)
    finally:
        os.unlink(tmp)


def render_outputs(result, paths):
    rendered = {}
    for fmt in paths:
        rendered[fmt] = (
            render_json(result)
            if fmt == "json"
            else (
                json.dumps(to_sarif(result), sort_keys=True, indent=2) + "\n"
                if fmt == "sarif"
                else render_markdown(result)
            )
        )
    for fmt, path in paths.items():
        if path is not None:
            write_atomic(path, rendered[fmt])
    return (
        next(iter(rendered.values()))
        if all(p is None for p in paths.values())
        else None
    )
