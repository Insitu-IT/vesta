#!/usr/bin/env python3
"""Validate local Iris v1 packs and prepare an immutable, bounded ConfigMap.

No cluster access. Only manifest-referenced assets enter the generated resource.
The separate projection is the optional site.json appearance value.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"
VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
FILE = r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+"
TOP = {"schema_version", "id", "version", "name", "description", "type", "author", "meta", "variant_schema", "categories", "assets"}
ASSET = {"label", "category", "tags", "content_type", "file", "variants", "default"}
MIMES = {"image/svg+xml", "image/png", "image/jpeg", "image/webp", "image/x-icon", "font/woff2", "text/x-tabler-icon"}
COLORS = {"primary", "success", "warning", "danger", "body-bg", "body-color"}
MAX_FILE = 256 * 1024
MAX_RESOURCE = 768 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text_value(value, limit):
    return isinstance(value, str) and 0 < len(value) <= limit and not re.search(r"[<>\x00-\x1f\x7f]", value)


def safe_path(value):
    return isinstance(value, str) and bool(re.fullmatch(FILE, value)) and not {".", ".."} & set(value.split("/"))


def validate_manifest(m):
    require(isinstance(m, dict) and not set(m) - TOP and type(m.get("schema_version")) is int and m["schema_version"] == 1, "Invalid manifest schema")
    require(isinstance(m.get("id"), str) and 2 <= len(m["id"]) <= 50 and re.fullmatch(SLUG, m["id"]), "Invalid pack id")
    require(isinstance(m.get("version"), str) and len(m["version"]) <= 32 and re.fullmatch(VERSION, m["version"]), "Invalid pack version")
    require(text_value(m.get("name"), 100) and m["name"].strip() and isinstance(m.get("type"), str) and re.fullmatch(SLUG, m["type"]), "Invalid pack name or type")
    for key, limit in (("description", 500), ("author", 255)):
        require(key not in m or isinstance(m[key], str) and len(m[key]) <= limit, "Invalid " + key)
    axes = m.get("variant_schema", {})
    require(isinstance(axes, dict) and len(axes) <= 8, "Invalid variant schema")
    for key, axis in axes.items():
        require(re.fullmatch(r"[a-z][a-z0-9_]*", key) and isinstance(axis, dict) and not set(axis) - {"label", "values", "default"}, "Invalid variant axis")
        require("label" not in axis or isinstance(axis["label"], str), "Invalid variant label")
        values = axis.get("values")
        require(isinstance(values, list) and 1 <= len(values) <= 32 and all(isinstance(v, str) and re.fullmatch(SLUG, v) for v in values), "Invalid variant values")
        require(len(set(values)) == len(values) and axis.get("default") in values, "Invalid default variant")
    categories = m.get("categories", {})
    require(isinstance(categories, dict), "Invalid categories")
    for key, category in categories.items():
        require(re.fullmatch(SLUG, key) and isinstance(category, dict) and not set(category) - {"label", "order"}, "Invalid category")
        require("label" not in category or isinstance(category["label"], str), "Invalid category label")
        require("order" not in category or type(category["order"]) is int, "Invalid category order")
    assets = m.get("assets")
    require(isinstance(assets, dict) and 1 <= len(assets) <= 64, "A pack requires 1 to 64 assets")
    for key, a in assets.items():
        require(re.fullmatch(SLUG, key) and isinstance(a, dict) and not set(a) - ASSET and a.get("content_type") in MIMES, "Invalid asset " + key)
        require("label" not in a or isinstance(a["label"], str), "Invalid asset label")
        require(("file" in a and "variants" not in a and "default" not in a)
                or ("file" not in a and "variants" in a and "default" in a), "Use file or variants and default")
        require("category" not in a or a["category"] in categories, "Unknown asset category")
        require("tags" not in a or isinstance(a["tags"], list) and all(isinstance(t, str) for t in a["tags"]), "Invalid asset tags")
        variants = a.get("variants", {})
        require(isinstance(variants, dict) and len(variants) <= 128 and ("variants" not in a or bool(variants) and bool(axes)), "Invalid asset variants")
        for variant in variants:
            parts = variant.split("/")
            require(0 < len(parts) <= len(axes) and all(p in axis["values"] for p, axis in zip(parts, axes.values())), "Invalid variant key")
        for file in asset_files(a):
            require(isinstance(file, str) and (bool(re.fullmatch(r"tabler://[a-z0-9-]+", file)) if a["content_type"] == "text/x-tabler-icon" else safe_path(file)), "Unsafe asset path")
    require(isinstance(m.get("meta", {}), dict), "Invalid metadata")
    metadata = m.get("meta", {})
    branding_key = "vesta" if "vesta" in metadata else "vnbui"
    v = metadata.get(branding_key, {})
    require(isinstance(v, dict) and not set(v) - {"schema_version", "product_name", "colors", "theme_colors", "font_family", "font_asset", "density"}, "Invalid appearance metadata")
    if branding_key in metadata:
        require(type(v.get("schema_version")) is int and v["schema_version"] in {1, 2}, "Invalid appearance metadata version")
    if "product_name" in v:
        require(text_value(v["product_name"], 80) and v["product_name"].strip(), "Invalid product name")
    colors = v.get("colors", {})
    require(isinstance(colors, dict) and not set(colors) - COLORS and all(isinstance(c, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", c) for c in colors.values()), "Invalid colors")
    if "theme_colors" in v:
        require(v.get("schema_version") == 2, "Theme colors require appearance metadata version 2")
        themes = v["theme_colors"]
        require(isinstance(themes, dict) and not set(themes) - {"light", "dark"}, "Invalid theme colors")
        for palette in themes.values():
            require(isinstance(palette, dict) and not set(palette) - COLORS and all(isinstance(c, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", c) for c in palette.values()), "Invalid theme palette")
    require(v.get("font_family", "system") in {"system", "sans", "serif", "mono"}, "Invalid font family")
    require(v.get("density", "comfortable") in {"comfortable", "compact"}, "Invalid density")
    require("font_asset" not in v or assets.get(v["font_asset"], {}).get("content_type") == "font/woff2", "Invalid font asset")
    return m


def asset_files(asset):
    return [asset[k] for k in ("file", "default") if k in asset] + list(asset.get("variants", {}).values())


def validate_content(data, mime):
    if mime == "image/svg+xml":
        require(not re.search(br"<!DOCTYPE|<!ENTITY|<\?", data, re.I), "SVG declarations are not allowed")
        try:
            root = ET.fromstring(data)
        except ET.ParseError as exc:
            raise ValueError("Invalid SVG") from exc
        allowed = {"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "defs", "linearGradient", "radialGradient", "stop", "clipPath", "mask", "use", "symbol", "title", "desc", "text", "tspan"}
        svg_namespace = "http://www.w3.org/2000/svg"
        xml_namespace = "http://www.w3.org/XML/1998/namespace"
        xlink_namespace = "http://www.w3.org/1999/xlink"

        def expanded_name(name):
            return name[1:].split("}", 1) if name.startswith("{") else ("", name)

        require(expanded_name(root.tag)[1] == "svg", "SVG root required")
        for node in root.iter():
            namespace, local = expanded_name(node.tag)
            require(namespace == svg_namespace and local in allowed, "Unsupported SVG element or namespace")
            for key, value in node.attrib.items():
                namespace, local = expanded_name(key)
                require(namespace in {"", svg_namespace, xml_namespace, xlink_namespace}, "Unsupported SVG attribute namespace")
                require(namespace != xml_namespace or local in {"space", "lang"}, "Unsupported XML attribute")
                require(namespace != xlink_namespace or local == "href", "Unsupported XLink attribute")
                name = local.lower()
                require(not name.startswith("on") and name not in {"style", "src"}, "Active SVG attribute")
                if name == "href":
                    require(bool(re.fullmatch(r"#[A-Za-z_][A-Za-z0-9_.:-]*", value)), "External SVG reference")
                require(not re.search(r"(?:https?:|data:|javascript:|@import)", value, re.I), "External SVG content")
                if "url(" in value.lower():
                    require(bool(re.fullmatch(r"url\(#[A-Za-z_][A-Za-z0-9_.:-]*\)", value)), "External SVG URL")
    else:
        signatures = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff", "image/x-icon": b"\x00\x00\x01\x00", "font/woff2": b"wOF2"}
        valid = data.startswith(signatures[mime]) if mime in signatures else mime == "image/webp" and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
        require(valid, "Asset content does not match its declared type")


def read_regular(root, relative, limit=MAX_FILE):
    candidate = root
    require(not root.is_symlink(), "Pack directory must not be a symlink")
    for part in Path(relative).parts:
        candidate /= part
        require(not candidate.is_symlink(), "Pack assets must not be symlinks")
    require(candidate.is_file() and candidate.stat().st_size <= limit, "Missing or oversized asset")
    return candidate.read_bytes()


def load_pack(root):
    m = validate_manifest(json.loads(read_regular(root, "manifest.json", 65536)))
    prefix = f"packs/{m['id']}/{m['version']}"
    files = {prefix + "/manifest.json": json.dumps(m, ensure_ascii=False, separators=(",", ":")).encode()}
    for a in m["assets"].values():
        if a["content_type"] == "text/x-tabler-icon":
            continue
        for file in asset_files(a):
            data = read_regular(root, file)
            validate_content(data, a["content_type"])
            files[prefix + "/" + file] = data
    return "/appearance/" + prefix, files


def prepare(active, previous, namespace, resource_prefix="vesta"):
    require(type(resource_prefix) is str and resource_prefix in {"vesta", "vnbui"}, "resource_prefix must be vesta or vnbui")
    require(re.fullmatch(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?", namespace), "Invalid namespace")
    active_path, files = load_pack(Path(active))
    config = {"schema_version": 1, "active_pack": active_path}
    if previous:
        previous_path, previous_files = load_pack(Path(previous))
        require(previous_path != active_path, "Previous pack must have a different id or version")
        config["previous_pack"] = previous_path
        files.update(previous_files)
    files["config.json"] = json.dumps(config, separators=(",", ":")).encode()
    require(len(files) <= 512, "Active and previous packs exceed the 512 projection item limit")
    data, items, payload_keys = {}, [], {}
    for i, (path, payload) in enumerate(sorted(files.items())):
        # Revisions commonly retain identical artwork. One ConfigMap key can
        # project to both versioned paths without storing those bytes twice.
        key = payload_keys.get(payload)
        if key is None:
            key = f"asset-{i:03}"
            payload_keys[payload] = key
            data[key] = base64.b64encode(payload).decode()
        items.append({"key": key, "path": path})
    fingerprint = hashlib.sha256(json.dumps([data, items], sort_keys=True).encode()).hexdigest()[:20]
    name = resource_prefix + "-appearance-" + fingerprint
    resource = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": name, "namespace": namespace}, "immutable": True, "binaryData": data}
    require(len(json.dumps(resource).encode()) <= MAX_RESOURCE, "Active and previous packs exceed the 768 KiB resource limit")
    return resource, {"config_map": name, "items": items}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--active", required=True, type=Path)
    p.add_argument("--previous", type=Path)
    p.add_argument("--namespace", required=True)
    p.add_argument("--resource-prefix", choices=("vesta", "vnbui"), default="vesta")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--projection-output", required=True, type=Path)
    a = p.parse_args()
    resource, projection = prepare(a.active, a.previous, a.namespace, a.resource_prefix)
    # Never overwrite an operator's earlier artifact or follow an output symlink.
    for path, value in ((a.output, resource), (a.projection_output, projection)):
        with path.open("x") as f:
            json.dump(value, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print("Prepared " + resource["metadata"]["name"] + "; nothing applied")


if __name__ == "__main__":
    main()
