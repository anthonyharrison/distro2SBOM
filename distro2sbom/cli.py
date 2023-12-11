# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
import textwrap
from collections import ChainMap
from pathlib import Path

from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM

from distro2sbom.distrobuilder.dpkgbuilder import DpkgBuilder
from distro2sbom.distrobuilder.rpmbuilder import RpmBuilder
from distro2sbom.distrobuilder.windowsbuilder import WindowsBuilder
from distro2sbom.version import VERSION

# CLI processing

# Required support applications for package metadata information
required_apps = {"deb": "dpkg", "rpm": "yum"}


def inpath(binary):
    """Check to see if san application is available in the path."""
    if sys.platform == "win32":
        return any(
            list(
                map(
                    lambda dirname: (Path(dirname) / (binary + ".exe")).is_file(),
                    os.environ.get("PATH", "").split(";"),
                )
            )
        )
    return any(
        list(
            map(
                lambda dirname: (Path(dirname) / binary).is_file(),
                os.environ.get("PATH", "").split(":"),
            )
        )
    )


def main(argv=None):

    argv = argv or sys.argv
    app_name = "distro2sbom"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            Distro2Sbom generates a Software Bill of Materials for the
            specified package or distribution.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "--distro",
        action="store",
        default="auto",
        choices=["rpm", "deb", "windows", "auto"],
        help="type of distribution (default: auto)",
    )
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        help="name of distribution file",
    )
    input_group.add_argument(
        "-n",
        "--name",
        action="store",
        help="name of distribution",
    )
    input_group.add_argument(
        "-r",
        "--release",
        action="store",
        help="release identity of distribution",
    )
    input_group.add_argument(
        "-p",
        "--package",
        action="store",
        help="identity of package within distribution",
    )
    input_group.add_argument(
        "-s",
        "--system",
        action="store_true",
        default=False,
        help="generate SBOM for installed system",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) (default: tag)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "distro": "auto",
        "input_file": "",
        "output_file": "",
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
        "name": None,
        "release": None,
        "package": "",
        "system": False,
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    if args["distro"] == "":
        print("[ERROR] distro type must be specified.")
        return -1
    elif args["name"] is not None and args["release"] is None:
        print("[ERROR] distro release must be specified.")
        return -1
    elif args["name"] is None and args["release"] is not None:
        print("[ERROR] distro name must be specified.")
        return -1
    elif args["input_file"] == "" and args["package"] == "" and not args["system"]:
        print("[ERROR] distro file or package name must be specified.")
        return -1

    # Ensure format is aligned with type of SBOM
    bom_format = args["format"]
    if args["sbom"] != "spdx" and bom_format in ["tag", "yaml"]:
        # Only json format valid for CycloneDX
        bom_format = "json"

    if args["debug"]:
        print("Distro type:", args["distro"])
        print("Input file:", args["input_file"])
        print("Distro name:", args["name"])
        print("Distro release:", args["release"])
        print("Package:", args["package"])
        print("System SBOM:", args["system"])
        print("SBOM type:", args["sbom"])
        print("Format:", bom_format)
        print("Output file:", args["output_file"])

    if args["distro"] == "auto":
        # determine distro type based on availability of key application
        distro_type = None
        for distro in required_apps:
            if inpath(required_apps[distro]):
                distro_type = distro
                break
        if distro_type is None:
            print("[ERROR] Unable to determine distro type.")
            return -1
    else:
        distro_type = args["distro"]
        # Check required application available to produce package level SBOM
        if args["package"] > "" and not inpath(required_apps[distro_type]):
            print(
                "[ERROR] Unable to produce package information for specified distribution."
            )
            return -1

    if distro_type == "deb":
        sbom_build = DpkgBuilder(args["name"], args["release"], args["debug"])
    elif distro_type == "rpm":
        sbom_build = RpmBuilder(args["name"], args["release"], args["debug"])
    elif distro_type == "windows":
        sbom_build = WindowsBuilder(args["name"], args["release"], args["debug"])

    if args["input_file"] != "":
        # Check file exists
        filePath = Path(args["input_file"])
        # Check path exists and is a valid file
        if filePath.exists() and filePath.is_file():
            # Assume that processing can proceed
            sbom_build.parse_data(args["input_file"])
        else:
            print(f"[ERROR] Unable to locate file {args['input_file']}")
            return -1
    elif args["system"]:
        if args["debug"]:
            print("This may take some time...")
        sbom_build.process_system()
    else:
        sbom_build.process_distro_package(args["package"])

    # Only generate if we have some data to process

    if len(sbom_build.get_packages()) > 0:
        # Generate SBOM file
        distro_sbom = SBOM()
        distro_sbom.add_packages(sbom_build.get_packages())
        distro_sbom.add_relationships(sbom_build.get_relationships())

        sbom_gen = SBOMGenerator(
            sbom_type=args["sbom"],
            format=bom_format,
            application=app_name,
            version=VERSION,
        )
        sbom_gen.generate(
            project_name=sbom_build.get_parent(),
            sbom_data=distro_sbom.get_sbom(),
            filename=args["output_file"],
        )
    else:
        if args["package"] != "":
            print(f"[ERROR] Unable to locate package {args['package']}")
        return -1

    return 0


if __name__ == "__main__":
    sys.exit(main())
