# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import re

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship

from distro2sbom.distrobuilder.distrobuilder import DistroBuilder


class DpkgBuilder(DistroBuilder):
    def __init__(self, name, release, debug=False):
        super().__init__(debug)
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.distro_packages = []
        self.name = name.replace(" ", "-")
        self.release = release
        self.parent = f"Distro-{self.name}"

    def parse_data(self, filename):
        # Process file containing installed applications
        with open(filename) as dir_file:
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
            self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
            # Store package data
            self.sbom_packages[
                (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
            ] = self.sbom_package.get_package()
            self.sbom_relationship.initialise()
            self.sbom_relationship.set_relationship(
                self.parent, "DESCRIBES", distro_root
            )
            self.sbom_relationships.append(self.sbom_relationship.get_relationship())
            for line in lines:
                # Only process installed packages
                if line[:2] == "ii":
                    line_element = re.sub(
                        " +", " ", line[2:].strip().rstrip("\n")
                    ).split(" ")
                    self.sbom_package.initialise()
                    package = line_element[0].lower().replace("_", "-")
                    version = line_element[1]
                    self.sbom_package.set_name(package)
                    self.sbom_package.set_version(version)
                    self.sbom_package.set_type("application")
                    self.sbom_package.set_filesanalysis(False)
                    license = "NOASSERTION"
                    self.sbom_package.set_licensedeclared(license)
                    self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
                    description = " ".join(n for n in line_element[3:])
                    self.sbom_package.set_summary(description)
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
                    self.sbom_relationships.append(
                        self.sbom_relationship.get_relationship()
                    )

    def get(self, attribute):
        if attribute in self.metadata:
            return self.metadata[attribute].lstrip()
        return ""

    def process_package(self, package_name, parent="-"):
        if self.debug:
            print(f"Process package {package_name}. Parent {parent}")
        # Check if we have already processed this package
        if package_name in self.distro_packages:
            self.sbom_relationship.initialise()
            self.sbom_relationship.set_relationship(
                parent.lower(), "DEPENDS_ON", package_name.lower().replace("_", "-")
            )
            self.sbom_relationships.append(self.sbom_relationship.get_relationship())
            return 0
        self.distro_packages.append(package_name)
        out = self.run_program(f"dpkg -s {package_name}")
        # If package not found, no metadata returned
        if len(out) > 0:
            self.metadata = {}
            for line in out:
                if ":" in line:
                    entry = line.split(":")
                    # store all data after keyword
                    self.metadata[entry[0]] = (
                        line.split(f"{entry[0]}:", 1)[1].strip().rstrip("\n")
                    )
            self.sbom_package.initialise()
            package = self.get("Package").lower().replace("_", "-")
            version = self.get("Version")
            self.sbom_package.set_name(package)
            self.sbom_package.set_version(version)
            self.sbom_package.set_filesanalysis(False)
            license = "NOASSERTION"
            self.sbom_package.set_licensedeclared(license)
            self.sbom_package.set_licenseconcluded(license)
            supplier = self.get("Maintainer")
            if len(supplier.split()) > 3:
                self.sbom_package.set_supplier(
                    "Organization", self.format_supplier(supplier)
                )
            elif len(supplier) > 1:
                self.sbom_package.set_supplier("Person", self.format_supplier(supplier))
            else:
                self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
            if self.get("Description") != "":
                self.sbom_package.set_summary(self.get("Description"))
            if self.get("Homepage") != "":
                self.sbom_package.set_homepage(self.get("Homepage"))
            # Store package data
            self.sbom_packages[
                (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
            ] = self.sbom_package.get_package()
            # Add relationship
            self.sbom_relationship.initialise()
            if parent != "-":
                self.sbom_relationship.set_relationship(
                    parent.lower(), "DEPENDS_ON", package
                )
            else:
                self.sbom_relationship.set_relationship(
                    self.parent, "DESCRIBES", package
                )
            self.sbom_relationships.append(self.sbom_relationship.get_relationship())
        elif self.debug:
            print(f"Package {package_name} not found")
        return len(out) > 0

    def analyze(self, parent, dependencies):
        if len(dependencies) == 0:
            return
        else:
            for r in dependencies.split(","):
                # Remove version string information
                dependency = r.strip().split(" ")[0].replace(":any", "")
                if len(dependency) > 0 and self.process_package(dependency, parent):
                    self.analyze(dependency.strip(), self.get("Depends"))

    def process_distro_package(self, module_name):
        self.parent = f"{self.name}-{self.release}-Package-{module_name}"
        if self.process_package(module_name):
            self.analyze(self.get("Package"), self.get("Depends"))
