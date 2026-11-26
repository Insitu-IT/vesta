#!/usr/bin/env python3
"""Regenerate the portable structural base into a NEW review directory.

Review the diff before replacing checked-in packaging/okd/kustomize/base.
Never point this at an existing directory or a customer overlay.
"""

import argparse
from pathlib import Path
import sys

# Keep the transferred release byte-for-byte verifiable after this tool runs.
sys.dont_write_bytecode = True
from render import STAGES, write_base_stage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("Output directory already exists")
    for stage in STAGES:
        write_base_stage(stage, args.output_dir / stage)


if __name__ == "__main__":
    main()
