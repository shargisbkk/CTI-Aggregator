from stix2 import parse

def parse_stix_objects(raw_objects: list[dict]) -> list[dict]:
    """
    Returns a list of normalized dicts:
      {stix_id, stix_type, spec_version, created, modified, raw}
    """
    out = []
    for o in raw_objects:
        try:
            obj = parse(o, allow_custom=True)
            raw = o  # keep original JSON

            out.append({
                "stix_id": getattr(obj, "id", raw.get("id", "")),
                "stix_type": getattr(obj, "type", raw.get("type", "")),
                "spec_version": raw.get("spec_version", ""),
                "created": raw.get("created"),
                "modified": raw.get("modified"),
                "raw": raw,
            })
        except Exception:
            # You can log errors here
            continue
    return out
