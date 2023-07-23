# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import platform
import re

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship

from distro2sbom.distrobuilder.distrobuilder import DistroBuilder


class WindowsBuilder(DistroBuilder):
    def __init__(self, name, release, debug=False):
        super().__init__(debug)
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.distro_packages = []
        if name is not None:
            self.name = name.replace(" ", "-")
        else:
            self.name = "Windows"
        if release is not None:
            self.release = release
        else:
            self.release = platform.version()
        self.parent = f"Distro-{self.name}"

    def get_data(self):
        pass

    def parse_data(self, filename):
        # Process product file
        metadata = {}
        # Files generated on Windows appear to be UTF-16 little endian
        with open(filename, encoding="utf-16-le") as dir_file:
            lines = dir_file.readlines()
        if len(lines) > 0:
            # Something to process
            distro_root = self.name.lower().replace("_", "-")
            self.sbom_package.initialise()
            self.sbom_package.set_name(distro_root)
            self.sbom_package.set_version(self.release)
            self.sbom_package.set_type("operating-system")
            self.sbom_package.set_filesanalysis(False)
            license = "NOASSERTION"
            self.sbom_package.set_licensedeclared(license)
            self.sbom_package.set_supplier("Organisation", "Microsoft Corporation")
            # Store package data
            self.sbom_packages[
                (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
            ] = self.sbom_package.get_package()
            distro_id = self.sbom_package.get_value("id")
            self.sbom_relationship.initialise()
            self.sbom_relationship.set_relationship(
                self.parent, "DESCRIBES", distro_root
            )
            self.sbom_relationships.append(self.sbom_relationship.get_relationship())

            for line in lines:
                # Process non-blank lines
                processed_line = line.strip().rstrip("\n")
                if len(processed_line) > 0:
                    line_element = re.sub(" +", " ", processed_line).split(":")
                    if len(line_element) > 1:
                        # Store product metadata
                        metadata[line_element[0].strip()] = line_element[1].strip()
                elif len(metadata) > 0:
                    if len(metadata["Name"]) > 0:
                        self.sbom_package.initialise()
                        package = metadata["Name"].lower().replace("_", "-")
                        version = metadata["Version"]
                        self.sbom_package.set_name(package)
                        self.sbom_package.set_version(version)
                        self.sbom_package.set_type("application")
                        self.sbom_package.set_filesanalysis(False)
                        license = "NOASSERTION"
                        self.sbom_package.set_licensedeclared(license)
                        self.sbom_package.set_supplier(
                            "Organisation", metadata["Vendor"]
                        )
                        self.sbom_package.set_summary(metadata["Caption"])
                        # Store package data
                        self.sbom_packages[
                            (
                                self.sbom_package.get_name(),
                                self.sbom_package.get_value("version"),
                            )
                        ] = self.sbom_package.get_package()
                        self.sbom_relationship.initialise()
                        self.sbom_relationship.set_relationship(
                            distro_root, "DEPENDS_ON", package
                        )
                        # Ids are required in case multiple versions of same package installed
                        self.sbom_relationship.set_relationship_id(
                            distro_id, self.sbom_package.get_value("id")
                        )
                        self.sbom_relationships.append(
                            self.sbom_relationship.get_relationship()
                        )
                    metadata = {}

    def process_distro_package(self, module_name):
        print("[ERROR] Feature not available")

    def get_system(self):
        print("[ERROR] Feature not available")
