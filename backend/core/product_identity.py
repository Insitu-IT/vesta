"""Product display identity from the same immutable pack mounted in the UI.

Appearance never changes protocol identifiers, licensing or authorization.
"""

import json
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET

# Mirrored standalone installer validation; parity fixtures guard this contract.
SLUG = r"[a-z0-9]+(?:-[a-z0-9]+)*"
VERSION = r"[0-9]+\.[0-9]+\.[0-9]+"
FILE = r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+"
TOP = {
    "schema_version",
    "id",
    "version",
    "name",
    "description",
    "type",
    "author",
    "meta",
    "variant_schema",
    "categories",
    "assets",
}
ASSET = {"label", "category", "tags", "content_type", "file", "variants", "default"}
MIMES = {
    "image/svg+xml",
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/x-icon",
    "font/woff2",
    "text/x-tabler-icon",
}
COLORS = {"primary", "success", "warning", "danger", "body-bg", "body-color"}
MAX_FILE = 256 * 1024
MAX_RESOURCE = 768 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def text_value(value, limit):
    return (
        isinstance(value, str)
        and 0 < len(value) <= limit
        and not re.search(r"[<>\x00-\x1f\x7f]", value)
    )


def safe_path(value):
    return (
        isinstance(value, str)
        and bool(re.fullmatch(FILE, value))
        and not {".", ".."} & set(value.split("/"))
    )


def validate_manifest(m):
    require(
        isinstance(m, dict)
        and not set(m) - TOP
        and type(m.get("schema_version")) is int
        and m["schema_version"] == 1,
        "Invalid manifest schema",
    )
    require(
        isinstance(m.get("id"), str)
        and 2 <= len(m["id"]) <= 50
        and re.fullmatch(SLUG, m["id"]),
        "Invalid pack id",
    )
    require(
        isinstance(m.get("version"), str)
        and len(m["version"]) <= 32
        and re.fullmatch(VERSION, m["version"]),
        "Invalid pack version",
    )
    require(
        text_value(m.get("name"), 100)
        and m["name"].strip()
        and isinstance(m.get("type"), str)
        and re.fullmatch(SLUG, m["type"]),
        "Invalid pack name or type",
    )
    for key, limit in (("description", 500), ("author", 255)):
        require(
            key not in m or isinstance(m[key], str) and len(m[key]) <= limit,
            "Invalid " + key,
        )
    axes = m.get("variant_schema", {})
    require(isinstance(axes, dict) and len(axes) <= 8, "Invalid variant schema")
    for key, axis in axes.items():
        require(
            re.fullmatch(r"[a-z][a-z0-9_]*", key)
            and isinstance(axis, dict)
            and not set(axis) - {"label", "values", "default"},
            "Invalid variant axis",
        )
        require(
            "label" not in axis or isinstance(axis["label"], str),
            "Invalid variant label",
        )
        values = axis.get("values")
        require(
            isinstance(values, list)
            and 1 <= len(values) <= 32
            and all(isinstance(v, str) and re.fullmatch(SLUG, v) for v in values),
            "Invalid variant values",
        )
        require(
            len(set(values)) == len(values) and axis.get("default") in values,
            "Invalid default variant",
        )
    categories = m.get("categories", {})
    require(isinstance(categories, dict), "Invalid categories")
    for key, category in categories.items():
        require(
            re.fullmatch(SLUG, key)
            and isinstance(category, dict)
            and not set(category) - {"label", "order"},
            "Invalid category",
        )
        require(
            "label" not in category or isinstance(category["label"], str),
            "Invalid category label",
        )
        require(
            "order" not in category or type(category["order"]) is int,
            "Invalid category order",
        )
    assets = m.get("assets")
    require(
        isinstance(assets, dict) and 1 <= len(assets) <= 64,
        "A pack requires 1 to 64 assets",
    )
    for key, a in assets.items():
        require(
            re.fullmatch(SLUG, key)
            and isinstance(a, dict)
            and not set(a) - ASSET
            and a.get("content_type") in MIMES,
            "Invalid asset " + key,
        )
        require("label" not in a or isinstance(a["label"], str), "Invalid asset label")
        require(
            ("file" in a and "variants" not in a and "default" not in a)
            or ("file" not in a and "variants" in a and "default" in a),
            "Use file or variants and default",
        )
        require(
            "category" not in a or a["category"] in categories, "Unknown asset category"
        )
        require(
            "tags" not in a
            or isinstance(a["tags"], list)
            and all(isinstance(t, str) for t in a["tags"]),
            "Invalid asset tags",
        )
        variants = a.get("variants", {})
        require(
            isinstance(variants, dict)
            and len(variants) <= 128
            and ("variants" not in a or bool(variants) and bool(axes)),
            "Invalid asset variants",
        )
        for variant in variants:
            parts = variant.split("/")
            require(
                0 < len(parts) <= len(axes)
                and all(p in axis["values"] for p, axis in zip(parts, axes.values())),
                "Invalid variant key",
            )
        for file in asset_files(a):
            require(
                isinstance(file, str)
                and (
                    bool(re.fullmatch(r"tabler://[a-z0-9-]+", file))
                    if a["content_type"] == "text/x-tabler-icon"
                    else safe_path(file)
                ),
                "Unsafe asset path",
            )
    require(isinstance(m.get("meta", {}), dict), "Invalid metadata")
    metadata = m.get("meta", {})
    branding_key = "vesta" if "vesta" in metadata else "vnbui"
    v = metadata.get(branding_key, {})
    require(
        isinstance(v, dict)
        and not set(v)
        - {
            "schema_version",
            "product_name",
            "colors",
            "theme_colors",
            "font_family",
            "font_asset",
            "density",
        },
        "Invalid appearance metadata",
    )
    if branding_key in metadata:
        require(
            type(v.get("schema_version")) is int and v["schema_version"] in {1, 2},
            "Invalid appearance metadata version",
        )
    if "product_name" in v:
        require(
            text_value(v["product_name"], 80) and v["product_name"].strip(),
            "Invalid product name",
        )
    colors = v.get("colors", {})
    require(
        isinstance(colors, dict)
        and not set(colors) - COLORS
        and all(
            isinstance(c, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", c)
            for c in colors.values()
        ),
        "Invalid colors",
    )
    if "theme_colors" in v:
        require(
            v.get("schema_version") == 2,
            "Theme colors require appearance metadata version 2",
        )
        themes = v["theme_colors"]
        require(
            isinstance(themes, dict) and not set(themes) - {"light", "dark"},
            "Invalid theme colors",
        )
        for palette in themes.values():
            require(
                isinstance(palette, dict)
                and not set(palette) - COLORS
                and all(
                    isinstance(c, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", c)
                    for c in palette.values()
                ),
                "Invalid theme palette",
            )
    require(
        v.get("font_family", "system") in {"system", "sans", "serif", "mono"},
        "Invalid font family",
    )
    require(
        v.get("density", "comfortable") in {"comfortable", "compact"}, "Invalid density"
    )
    require(
        "font_asset" not in v
        or assets.get(v["font_asset"], {}).get("content_type") == "font/woff2",
        "Invalid font asset",
    )
    return m


def asset_files(asset):
    return [asset[k] for k in ("file", "default") if k in asset] + list(
        asset.get("variants", {}).values()
    )


def validate_content(data, mime):
    if mime == "image/svg+xml":
        require(
            not re.search(rb"<!DOCTYPE|<!ENTITY|<\?", data, re.I),
            "SVG declarations are not allowed",
        )
        try:
            root = ET.fromstring(data)
        except ET.ParseError as exc:
            raise ValueError("Invalid SVG") from exc
        allowed = {
            "svg",
            "g",
            "path",
            "rect",
            "circle",
            "ellipse",
            "line",
            "polyline",
            "polygon",
            "defs",
            "linearGradient",
            "radialGradient",
            "stop",
            "clipPath",
            "mask",
            "use",
            "symbol",
            "title",
            "desc",
            "text",
            "tspan",
        }
        svg_namespace = "http://www.w3.org/2000/svg"
        xml_namespace = "http://www.w3.org/XML/1998/namespace"
        xlink_namespace = "http://www.w3.org/1999/xlink"

        def expanded_name(name):
            return name[1:].split("}", 1) if name.startswith("{") else ("", name)

        require(expanded_name(root.tag)[1] == "svg", "SVG root required")
        for node in root.iter():
            namespace, local = expanded_name(node.tag)
            require(
                namespace == svg_namespace and local in allowed,
                "Unsupported SVG element or namespace",
            )
            for key, value in node.attrib.items():
                namespace, local = expanded_name(key)
                require(
                    namespace in {"", svg_namespace, xml_namespace, xlink_namespace},
                    "Unsupported SVG attribute namespace",
                )
                require(
                    namespace != xml_namespace or local in {"space", "lang"},
                    "Unsupported XML attribute",
                )
                require(
                    namespace != xlink_namespace or local == "href",
                    "Unsupported XLink attribute",
                )
                name = local.lower()
                require(
                    not name.startswith("on") and name not in {"style", "src"},
                    "Active SVG attribute",
                )
                if name == "href":
                    require(
                        bool(re.fullmatch(r"#[A-Za-z_][A-Za-z0-9_.:-]*", value)),
                        "External SVG reference",
                    )
                require(
                    not re.search(
                        r"(?:https?:|data:|javascript:|@import)", value, re.I
                    ),
                    "External SVG content",
                )
                if "url(" in value.lower():
                    require(
                        bool(re.fullmatch(r"url\(#[A-Za-z_][A-Za-z0-9_.:-]*\)", value)),
                        "External SVG URL",
                    )
    else:
        signatures = {
            "image/png": b"\x89PNG\r\n\x1a\n",
            "image/jpeg": b"\xff\xd8\xff",
            "image/x-icon": b"\x00\x00\x01\x00",
            "font/woff2": b"wOF2",
        }
        valid = (
            data.startswith(signatures[mime])
            if mime in signatures
            else mime == "image/webp" and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
        )
        require(valid, "Asset content does not match its declared type")


DEFAULT_PRODUCT_NAME = "Vesta"
PACK = re.compile(
    r"/appearance/(packs/([a-z0-9]+(?:-[a-z0-9]+)*)/([0-9]+\.[0-9]+\.[0-9]+))"
)


def _json(path):
    with path.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError("Oversized appearance metadata")
    return json.loads(data)


def product_name():
    """Use active, previous, then bundled identity without breaking report/email."""
    canonical = Path("/etc/vesta/appearance")
    inherited = (
        canonical
        if (canonical / "config.json").is_file()
        else Path("/etc/vnbui/appearance")
    )
    root = Path(os.getenv("APPEARANCE_ROOT", inherited))
    try:
        config = _json(root / "config.json")
        if (
            not isinstance(config, dict)
            or type(config.get("schema_version")) is not int
            or config["schema_version"] != 1
        ):
            return DEFAULT_PRODUCT_NAME
        for key in ("active_pack", "previous_pack"):
            path = config.get(key)
            match = PACK.fullmatch(path) if isinstance(path, str) else None
            if not match:
                continue
            try:
                base = root / match[1]
                manifest_path = base / "manifest.json"
                if not manifest_path.resolve().is_relative_to(root.resolve()):
                    continue
                manifest = validate_manifest(_json(manifest_path))
                if (
                    manifest.get("schema_version") != 1
                    or manifest.get("id") != match[2]
                    or manifest.get("version") != match[3]
                ):
                    continue
                metadata = manifest.get("meta", {})
                meta = metadata.get("vesta", metadata.get("vnbui", {}))
                name = meta.get("product_name", DEFAULT_PRODUCT_NAME)
                if (
                    not isinstance(name, str)
                    or not 1 <= len(name.strip()) <= 80
                    or re.search(r"[<>\x00-\x1f\x7f]", name)
                ):
                    continue
                complete = True
                for asset in manifest["assets"].values():
                    files = [
                        asset[k] for k in ("file", "default") if k in asset
                    ] + list(asset.get("variants", {}).values())
                    for file in files:
                        if asset.get("content_type") == "text/x-tabler-icon":
                            continue
                        if (
                            not isinstance(file, str)
                            or not re.fullmatch(
                                r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+", file
                            )
                            or {".", ".."} & set(file.split("/"))
                            or not (base / file).is_file()
                        ):
                            complete = False
                            continue
                        asset_path = base / file
                        if (
                            not asset_path.resolve().is_relative_to(root.resolve())
                            or asset_path.stat().st_size > MAX_FILE
                        ):
                            complete = False
                            continue
                        validate_content(asset_path.read_bytes(), asset["content_type"])
                if complete:
                    return name.strip()
            except (OSError, ValueError, TypeError, KeyError, AttributeError):
                continue
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return DEFAULT_PRODUCT_NAME
