"""
Loads the centralized type mapping from type_map.json.

Every adapter's raw ioc_type is lowercased and looked up in TYPE_MAP.
Unmapped types are dropped by normalize_one().

To add a new source type, edit type_map.json — no Python changes needed.
"""

import json
from pathlib import Path

_MAP_FILE = Path(__file__).with_name("type_map.json")
TYPE_MAP: dict[str, str] = json.loads(_MAP_FILE.read_text(encoding="utf-8"))
