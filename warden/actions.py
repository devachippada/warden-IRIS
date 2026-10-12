"""
warden/actions.py

The action registry: the only vocabulary the runtime understands.

Every action a plan can contain must resolve to a canonical action here,
either directly or through an alias. Anything that does not resolve is
`unknown`, and unknown actions are always rejected by policy.

Each canonical action declares:
    category    read | write | delete
    reversible  whether the effect can be undone without a backup
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ActionSpec:
    name: str
    category: str          # read | write | delete
    reversible: bool
    description: str


REGISTRY: dict[str, ActionSpec] = {
    spec.name: spec
    for spec in [
        ActionSpec("read_file",   "read",   True,  "Read a text file inside the workspace"),
        ActionSpec("list_dir",    "read",   True,  "List entries in a workspace directory"),
        ActionSpec("search_text", "read",   True,  "Search files in the workspace for a string"),
        ActionSpec("write_file",  "write",  False, "Create or overwrite a file (overwrite is irreversible)"),
        ActionSpec("append_file", "write",  True,  "Append text to a file"),
        ActionSpec("make_dir",    "write",  True,  "Create a directory"),
        ActionSpec("delete_file", "delete", False, "Delete a single file"),
    ]
}

# Aliases map the many names a model invents onto the canonical vocabulary.
# Deliberately conservative: vague catch-alls (shell, execute, process_data)
# are NOT aliased and therefore stay unknown.
ALIASES: dict[str, str] = {
    # read
    "file_read": "read_file", "cat": "read_file", "open_file": "read_file",
    "fetch_file": "read_file", "view_file": "read_file",
    "list_directory": "list_dir", "ls": "list_dir", "listdir": "list_dir",
    "search": "search_text", "grep": "search_text", "search_file": "search_text",
    "find_text": "search_text",
    # write
    "file_write": "write_file", "save_file": "write_file", "save": "write_file",
    "create_file": "write_file", "overwrite_file": "write_file",
    "append_to_file": "append_file", "file_append": "append_file",
    "mkdir": "make_dir", "create_dir": "make_dir", "create_directory": "make_dir",
    # delete
    "remove_file": "delete_file", "file_delete": "delete_file", "rm": "delete_file",
    "delete": "delete_file",
}

UNKNOWN = "unknown"


def canonical(action: str) -> str | None:
    """Return the canonical action name, or None if it is not recognised."""
    key = (action or "").strip().lower()
    if key in REGISTRY:
        return key
    return ALIASES.get(key)


def category(action: str) -> str:
    """read | write | delete | unknown"""
    name = canonical(action)
    return REGISTRY[name].category if name else UNKNOWN


def is_reversible(action: str) -> bool:
    name = canonical(action)
    return bool(name and REGISTRY[name].reversible)
