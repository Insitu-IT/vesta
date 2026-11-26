"""Remove reviewed unused font families before the dependency layer is committed."""

import csv
import hashlib
import io
from importlib.metadata import distribution
import json
from pathlib import Path

# Exact files from publisher reportlab-4.5.0-py3-none-any.whl, SHA256
# b8cc8996947d84e805368b47b2376070966f091d029351a0d8a1f238984c2c7f.
REVIEWED = {
    "DarkGarden-changelog.txt": "dbb09ff331d1597125f754d9426bb8cef78fb956397790de44269db8c0a9e54d",
    "DarkGarden-copying-gpl.txt": "1b2a567f289f66a143c56353e7b3d4fa5862514a5e3c5cfdf8b02ee5e5aaa953",
    "DarkGarden-copying.txt": "3cd1020510efa7f6b3166a5a2740f92bd664a695ea179e0bda442e74cd0ef3a4",
    "DarkGarden-readme.txt": "b327963fcf0d88333d293751dd0b113c8c02f35d61440f578a14681a8ea734a0",
    "DarkGarden.sfd": "7ff67c9eda02fc751f5ca04394109c38b2d723e105506e58141fc9363662d6ba",
    "DarkGardenMK.afm": "932bb1acc08358d87f326e891b78cde9e7ef60bfd4fb749cfb48ab9e2a2fe6eb",
    "DarkGardenMK.pfb": "3633d5aed5c0fc3ec9302ee6995d0bb87a2926793ede5bb654287d9cb896ec95",
    "Vera.ttf": "c4c45690b345435b2cba52ecabe275f05e49b389b39fe68ad03afbb551288d3d",
    "VeraBI.ttf": "fca0d4eeac1ced7e75e1b2274c869a351d2d83b5ed1f61d249e7bcc477c33ebe",
    "VeraBd.ttf": "cc037385e4d55bfde89b13e03091ee93bf40c0c52ddd391ff031ab276f13b8e9",
    "VeraIt.ttf": "2adc684d518f45232c4ad1f56522f5a82a6904c31940373e1b7030beee20fb3a",
    "bitstream-vera-license.txt": "3361d054759a2fc686a2c058be82deaf9c2e6fe549be9004d7935a6c1736315d",
}


def prune(notice=Path("/usr/share/licenses/vnbui/python-pruning.json")):
    package = distribution("reportlab")
    if package.version != "4.5.0":
        raise RuntimeError("Review ReportLab font pruning before changing its version")
    fonts = Path(package.locate_file("reportlab/fonts"))
    actual = {
        p.name
        for p in fonts.iterdir()
        if p.name.startswith(("DarkGarden", "Vera"))
        or p.name == "bitstream-vera-license.txt"
    }
    if actual != set(REVIEWED):
        raise RuntimeError("ReportLab font inventory differs from reviewed wheel")
    # Validate the complete family, including sources and notices, before removal.
    for name, digest in REVIEWED.items():
        if hashlib.sha256((fonts / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError(
                "ReportLab font content differs from reviewed wheel: " + name
            )
    # Installed metadata must describe the pruned artifact. Raw RECORD consumers
    # and Python versions differ in whether they silently omit missing entries.
    record = Path(package.locate_file("reportlab-4.5.0.dist-info/RECORD"))
    original_record_sha256 = hashlib.sha256(record.read_bytes()).hexdigest()
    rows = list(csv.reader(io.StringIO(record.read_text())))
    excluded = {"reportlab/fonts/" + name for name in REVIEWED}
    matched = [row[0] for row in rows if row and row[0] in excluded]
    if len(matched) != len(excluded) or set(matched) != excluded:
        raise RuntimeError("ReportLab RECORD differs from reviewed font inventory")
    retained = io.StringIO(newline="")
    csv.writer(retained).writerows(
        row for row in rows if not row or row[0] not in excluded
    )
    for name in REVIEWED:
        (fonts / name).unlink()
    record.write_text(retained.getvalue(), encoding="utf-8", newline="")
    updated_record_sha256 = hashlib.sha256(record.read_bytes()).hexdigest()
    notice.parent.mkdir(parents=True, exist_ok=True)
    notice.write_text(
        json.dumps(
            {
                "reportlab_version": package.version,
                "reason": "Unused DarkGarden and Bitstream Vera families; standard-font metrics retained",
                "removed_files_sha256": REVIEWED,
                "installed_record_reconciled": True,
                "installed_record_sha256": {
                    "before": original_record_sha256,
                    "after": updated_record_sha256,
                },
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    prune()
