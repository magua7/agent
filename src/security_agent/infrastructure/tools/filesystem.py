"""Scope-constrained local file tools."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterator, Mapping
from pathlib import Path, PurePath
from typing import cast

from security_agent.contracts import RiskLevel, ToolExecutionContext, ToolResult
from security_agent.contracts.common import JSONObject, JSONValue
from security_agent.infrastructure.tools._scope import (
    authorized_file_roots,
    path_is_authorized,
    resolve_authorized_path,
)
from security_agent.infrastructure.tools.errors import InputValidationError, ScopeViolation
from security_agent.infrastructure.tools.validation import validate_arguments


class FileReadTool:
    """Read a bounded text file from an explicitly authorized root."""

    name = "file_read"
    description = "Read a bounded text file from an authorized filesystem root."
    capabilities = frozenset({"file.read"})
    risk_level = RiskLevel.LOW

    def __init__(self, *, max_file_bytes: int = 1_000_000) -> None:
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        self._max_file_bytes = max_file_bytes

    @property
    def input_schema(self) -> Mapping[str, JSONValue]:
        return {
            "type": "object",
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                "encoding": {
                    "type": "string",
                    "enum": ["utf-8", "utf-8-sig", "ascii", "latin-1"],
                },
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": self._max_file_bytes,
                },
            },
            "required": ["path"],
            "additionalProperties": False,
        }

    async def execute(
        self,
        context: ToolExecutionContext,
        arguments: Mapping[str, JSONValue],
    ) -> ToolResult:
        try:
            validate_arguments(self.input_schema, arguments)
            requested_path = cast(str, arguments["path"])
            encoding = cast(str, arguments.get("encoding", "utf-8"))
            requested_limit = cast(int, arguments.get("max_bytes", self._max_file_bytes))
            limit = min(self._max_file_bytes, context.max_output_bytes)
            if requested_limit > limit:
                raise InputValidationError(
                    f"$.max_bytes: must not exceed the execution limit of {limit} bytes"
                )
            path = resolve_authorized_path(context.scope, requested_path, require_directory=False)
            roots = authorized_file_roots(context.scope)
            content = await asyncio.to_thread(
                _read_bounded_file,
                path,
                requested_limit,
                roots,
            )
            try:
                output = content.decode(encoding, errors="strict")
            except UnicodeDecodeError as exc:
                raise InputValidationError(
                    f"file is not valid {encoding} text at byte {exc.start}"
                ) from exc
            output_size = len(output.encode("utf-8"))
            if output_size > context.max_output_bytes:
                raise InputValidationError(
                    "decoded file content exceeds the execution output byte limit"
                )
            return ToolResult(
                success=True,
                output=output,
                metadata={
                    "path": str(path),
                    "bytes_read": len(content),
                    "output_bytes": output_size,
                    "encoding": encoding,
                },
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return _file_failure(exc)


class FileSearchTool:
    """Search bounded files below authorized roots without invoking a shell."""

    name = "file_search"
    description = "Search text files under authorized roots with bounded results and reads."
    capabilities = frozenset({"file.search", "code.search"})
    risk_level = RiskLevel.LOW

    def __init__(
        self,
        *,
        max_results: int = 200,
        max_file_bytes: int = 1_000_000,
        max_files: int = 10_000,
        max_line_characters: int = 500,
    ) -> None:
        if min(max_results, max_file_bytes, max_files, max_line_characters) <= 0:
            raise ValueError("file search limits must be positive")
        self._max_results = max_results
        self._max_file_bytes = max_file_bytes
        self._max_files = max_files
        self._max_line_characters = max_line_characters

    @property
    def input_schema(self) -> Mapping[str, JSONValue]:
        return {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 4096},
                "root": {"type": "string", "minLength": 1, "maxLength": 4096},
                "glob": {"type": "string", "minLength": 1, "maxLength": 512},
                "case_sensitive": {"type": "boolean"},
                "max_results": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": self._max_results,
                },
            },
            "required": ["root", "query"],
            "additionalProperties": False,
        }

    async def execute(
        self,
        context: ToolExecutionContext,
        arguments: Mapping[str, JSONValue],
    ) -> ToolResult:
        try:
            validate_arguments(self.input_schema, arguments)
            query = cast(str, arguments["query"])
            glob = cast(str, arguments.get("glob", "*"))
            case_sensitive = cast(bool, arguments.get("case_sensitive", False))
            result_limit = cast(int, arguments.get("max_results", self._max_results))
            matcher = _make_matcher(query, case_sensitive=case_sensitive)
            roots = authorized_file_roots(context.scope)
            if not roots:
                raise ScopeViolation("file search denied: scope has no authorized file roots")
            requested_root = cast(str, arguments["root"])
            search_paths = (resolve_authorized_path(context.scope, requested_root),)
            outcome = await asyncio.to_thread(
                self._search,
                search_paths,
                roots,
                glob,
                matcher,
                result_limit,
            )
            matches = cast(list[JSONObject], outcome["matches"])
            output, output_truncated = _bounded_json_array(matches, context.max_output_bytes)
            if output_truncated:
                outcome["truncated"] = True
                outcome["matches_returned"] = len(json.loads(output))
            del outcome["matches"]
            outcome["output_truncated"] = output_truncated
            return ToolResult(success=True, output=output, metadata=outcome)
        except (OSError, RuntimeError, ValueError) as exc:
            return _file_failure(exc)

    def _search(
        self,
        search_paths: tuple[Path, ...],
        roots: tuple[Path, ...],
        glob: str,
        matcher: _LineMatcher,
        result_limit: int,
    ) -> JSONObject:
        matches: list[JSONObject] = []
        files_considered = 0
        files_scanned = 0
        files_skipped_large = 0
        files_skipped_binary = 0
        files_skipped_unauthorized = 0
        truncated = False
        for candidate in _iter_files(search_paths):
            if files_considered >= self._max_files:
                truncated = True
                break
            files_considered += 1
            try:
                resolved = candidate.resolve(strict=True)
            except (OSError, RuntimeError):
                continue
            if not path_is_authorized(resolved, roots):
                files_skipped_unauthorized += 1
                continue
            relative = _relative_to_any(resolved, roots)
            if relative is None or not _matches_glob(relative, glob):
                continue
            files_scanned += 1
            try:
                size = resolved.stat().st_size
            except OSError:
                continue
            if size > self._max_file_bytes:
                files_skipped_large += 1
                continue
            try:
                data = _read_bounded_file(resolved, self._max_file_bytes, roots)
            except (OSError, ValueError):
                continue
            if b"\x00" in data[:8192]:
                files_skipped_binary += 1
                continue
            text = data.decode("utf-8", errors="replace")
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not matcher(line):
                    continue
                clipped = line[: self._max_line_characters]
                matches.append(
                    {
                        "path": str(resolved),
                        "line": line_number,
                        "text": clipped,
                        "line_truncated": len(clipped) != len(line),
                    }
                )
                if len(matches) >= result_limit:
                    truncated = True
                    break
            if len(matches) >= result_limit:
                break
        return {
            "matches": cast(JSONValue, matches),
            "matches_returned": len(matches),
            "files_considered": files_considered,
            "files_scanned": files_scanned,
            "files_skipped_large": files_skipped_large,
            "files_skipped_binary": files_skipped_binary,
            "files_skipped_unauthorized": files_skipped_unauthorized,
            "truncated": truncated,
            "max_file_bytes": self._max_file_bytes,
            "max_files": self._max_files,
        }


class _LineMatcher:
    """Typed literal matcher used by the synchronous search worker."""

    def __init__(self, pattern: str, *, case_sensitive: bool) -> None:
        self._needle = pattern if case_sensitive else pattern.casefold()
        self._case_sensitive = case_sensitive

    def __call__(self, line: str) -> bool:
        haystack = line if self._case_sensitive else line.casefold()
        return self._needle in haystack


def _make_matcher(query: str, *, case_sensitive: bool) -> _LineMatcher:
    return _LineMatcher(query, case_sensitive=case_sensitive)


def _read_bounded_file(
    path: Path,
    limit: int,
    roots: tuple[Path, ...] = (),
) -> bytes:
    """Open once, bind checks to the handle, and re-check containment.

    ``resolve_authorized_path`` performs the initial authorization. The
    identity checks here close the usual gap where a symlink or parent
    directory is exchanged between that check and ``open``.
    """

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        resolved_while_open = path.resolve(strict=True)
        if roots and not path_is_authorized(resolved_while_open, roots):
            raise ScopeViolation("file changed to a path outside the authorized roots")
        if not os.path.samestat(opened, resolved_while_open.stat()):
            raise ScopeViolation("file identity changed between authorization and open")
        if opened.st_size > limit:
            raise ValueError(f"file size {opened.st_size} exceeds the {limit}-byte limit")
        content = handle.read(limit + 1)
        if not os.path.samestat(opened, os.fstat(handle.fileno())):
            raise ScopeViolation("opened file identity changed during the read")
    if len(content) > limit:
        raise ValueError(f"file content exceeds the {limit}-byte limit")
    resolved_after_read = path.resolve(strict=True)
    if roots and not path_is_authorized(resolved_after_read, roots):
        raise ScopeViolation("file changed to a path outside the authorized roots")
    if not os.path.samestat(opened, resolved_after_read.stat()):
        raise ScopeViolation("file identity changed during the read")
    return content


def _iter_files(search_paths: tuple[Path, ...]) -> Iterator[Path]:
    seen: set[Path] = set()
    for search_path in sorted(search_paths, key=lambda item: str(item).casefold()):
        if search_path.is_file():
            candidates = (search_path,)
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                yield candidate
            continue
        for directory, child_directories, filenames in os.walk(search_path, followlinks=False):
            child_directories.sort(key=str.casefold)
            for filename in sorted(filenames, key=str.casefold):
                candidate = Path(directory) / filename
                if candidate in seen:
                    continue
                if not candidate.is_file():
                    continue
                seen.add(candidate)
                yield candidate


def _relative_to_any(path: Path, roots: tuple[Path, ...]) -> PurePath | None:
    for root in roots:
        try:
            return path.relative_to(root)
        except ValueError:
            continue
    return None


def _matches_glob(path: PurePath, pattern: str) -> bool:
    if pattern == "*":
        return True
    return path.match(pattern) or path.name == pattern


def _bounded_json_array(values: list[JSONObject], byte_limit: int) -> tuple[str, bool]:
    kept = list(values)
    while True:
        output = json.dumps(kept, ensure_ascii=False, sort_keys=True)
        if len(output.encode("utf-8")) <= byte_limit:
            return output, len(kept) != len(values)
        if not kept:
            # ToolExecutionContext guarantees a positive limit. The empty JSON
            # array is two bytes; report an empty string only for a one-byte cap.
            return ("[]" if byte_limit >= 2 else ""), True
        kept.pop()


def _file_failure(exc: Exception) -> ToolResult:
    return ToolResult(
        success=False,
        error=f"{type(exc).__name__}: {exc}",
        metadata={"error_type": type(exc).__name__},
    )
