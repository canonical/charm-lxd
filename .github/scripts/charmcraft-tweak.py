#!/usr/bin/python3

"""Rewrite a charmcraft.yaml to embed the requirements.txt as charm-binary-python-packages."""

import pathlib
import sys
import yaml


def rewrite_charmcraft(directory: str, unneeded_build_pkgs: list[str]) -> None:
    """Rewrite a charmcraft.yaml to embed the requirements.txt as charm-binary-python-packages.

    Make sure the provided directory contains a charmcraft.yaml and a requirements.txt file.

    Example of charmcraft.yaml:
    type: charm
      - name: ubuntu
        channel: "22.04"
    parts:
      charm:
        build-packages:
          - ca-certificates
          - cargo
          - git
          - libffi-dev
          - libssl-dev
          - pkg-config
          - python3-dev
          - rustc

    Example of requirements.txt:
    pyopenssl >= 23.1.1
    pyyaml

    Example of charmcraft.yaml after running this script:
    type: charm
      - name: ubuntu
        channel: "22.04"
    parts:
      charm:
        build-packages:
          - ca-certificates
          - cargo
          - git
          - libffi-dev
          - libssl-dev
          - pkg-config
          - python3-dev
          - rustc
        charm-binary-python-packages:
          - pyopenssl >= 23.1.1
          - pyyaml
    """
    charmcraft_yaml = pathlib.Path(directory) / "charmcraft.yaml"
    requirements_txt = pathlib.Path(directory) / "requirements.txt"

    if not charmcraft_yaml.exists():
        sys.exit("charmcraft.yaml not found")
    if not requirements_txt.exists():
        sys.exit("requirements.txt not found")

    with open(charmcraft_yaml, "r") as f:
        charmcraft = yaml.safe_load(f)

    with open(requirements_txt, "r") as f:
        requirements = f.read().splitlines()

    # Ensure properly formatted charmcraft.yaml
    if "parts" not in charmcraft or "charm" not in charmcraft["parts"]:
        sys.exit("charmcraft.yaml is missing parts/charm")

    # Remove unneeded build packages
    build_pkgs = charmcraft["parts"]["charm"].get("build-packages", [])
    if unneeded_build_pkgs and build_pkgs:
        charmcraft["parts"]["charm"]["build-packages"] = [pkg for pkg in build_pkgs if pkg not in unneeded_build_pkgs]

    # Add requirements.txt as charm-binary-python-packages
    if "charm-binary-python-packages" not in charmcraft["parts"]["charm"]:
        charmcraft["parts"]["charm"]["charm-binary-python-packages"] = []
    charmcraft["parts"]["charm"]["charm-binary-python-packages"] += requirements

    yaml.dump(charmcraft, open(charmcraft_yaml, "w"), sort_keys=False)


if __name__ == "__main__":
    unneeded_build_pkgs: str = ""

    if len(sys.argv) < 2:
        sys.exit("Missing path to charm directory")
    if len(sys.argv) > 2:
        unneeded_build_pkgs = sys.argv[2]

    rewrite_charmcraft(sys.argv[1], unneeded_build_pkgs.split(","))
