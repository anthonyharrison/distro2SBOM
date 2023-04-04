# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner

from distro2sbom.distrobuilder.distrobuilder import DistroBuilder


class RpmBuilder(DistroBuilder):
    def __init__(self, name, release, debug=False):
        super().__init__(debug)
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.license = LicenseScanner()
        self.distro_packages = []
        self.name = name.replace(" ", "-")
        self.release = release
        self.parent = f"Distro-{self.name}"

    def get_data(self):
        pass

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
                # Clear metadata in any case for each line
                self.metadata = {}
                line_element = line.strip().rstrip("\n")
                # Extract the package name (without extension) - make lowercase
                item = os.path.splitext(os.path.basename(line_element))[0].lower()
                # Parse line PRODUCT-VERSION[-Other]?. If pattern not followed ignore...
                # Version assumed to start with digit.
                product_version = re.search(r"-\d[.\d]*[a-z0-9]*", item)
                if product_version is not None:
                    # Find
                    package = item[: product_version.start()].lower().replace("_", "-")
                    out = self.run_program(f"rpm -qi {package}")
                    # Parse output
                    if len(out) > 0:
                        for line in out:
                            if ":" in line:
                                line_entry = re.sub(" +", " ", line.strip().rstrip("\n"))
                                entry = line_entry.split(":")
                                keyword = entry[0].strip()
                                # store all data after keyword
                                self.metadata[keyword] = (
                                    line_entry[len(keyword) + 2 :].strip().rstrip("\n")
                                )
                    if len(self.metadata) == 0:
                        # Package not installed so no metadata
                        continue
                    self.sbom_package.initialise()
                    version = product_version.group(0)[1:]
                    self.sbom_package.set_name(package)
                    self.sbom_package.set_version(version)
                    self.sbom_package.set_type("application")
                    self.sbom_package.set_filesanalysis(False)
                    license = self.license.find_license(self.get("License"))
                    # Report license as reported by metadata. If not valid SPDX, report NOASSERTION
                    if license != self.get("License"):
                        self.sbom_package.set_licensedeclared("NOASSERTION")
                    else:
                        self.sbom_package.set_licensedeclared(license)
                    # Report license if valid SPDX identifier
                    self.sbom_package.set_licenseconcluded(license)
                    # Add comment if metadata license was modified
                    if len(self.get("License")) > 0 and license != self.get("License"):
                        self.sbom_package.set_licensecomments(
                            f"{self.get('Name')} declares {self.get('License')} which is not a valid SPDX License identifier or expression."
                        )
                    self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
                    if self.get("Summary") != "":
                        self.sbom_package.set_summary(self.get("Summary"))
                    if self.get("URL") != "":
                        self.sbom_package.set_homepage(self.get("URL"))
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
                parent, "DEPENDS_ON", package_name.replace("_", "-")
            )
            self.sbom_relationships.append(self.sbom_relationship.get_relationship())
            return 0
        self.distro_packages.append(package_name)
        out = self.run_program(f"rpm -qi {package_name}")
        # If package not found, no metadata returned
        if len(out) > 0:
            self.metadata = {}
            for line in out:
                if ":" in line:
                    line_entry = re.sub(" +", " ", line.strip().rstrip("\n"))
                    entry = line_entry.split(":")
                    keyword = entry[0].strip()
                    # store all data after keyword
                    self.metadata[keyword] = (
                        line_entry[len(keyword) + 2 :].strip().rstrip("\n")
                    )
            if len(self.metadata) == 0:
                # Package not installed so no metadata
                return False
            # Now find package dependencies
            dependencies_out = self.run_program(
                f"yum repoquery --deplist {package_name}"
            )
            requires = []
            for line in dependencies_out:
                # Only process lines with provider
                if "provider:" not in line:
                    continue
                # Remove keyword from line
                line_element = line.lstrip().strip().rstrip("\n")[9:]
                # Dependency is app-version-release-architecture
                # Extract the package name (without extension) - make lowercase
                item = os.path.splitext(os.path.basename(line_element))[0].lower()
                # Parse line PRODUCT-VERSION[-Other]?. If pattern not followed ignore...
                # Version assumed to start with digit.
                product_version = re.search(r"-\d[.\d]*[a-z0-9]*", item)
                if product_version is not None:
                    dependency = item[: product_version.start()].strip()
                    if (
                        len(dependency) > 0
                        and dependency not in requires
                        and dependency != package_name
                    ):
                        requires.append(dependency)
            self.metadata["Depends"] = ",".join(n for n in requires)
            self.sbom_package.initialise()
            package = self.get("Name")
            version = self.get("Version")
            self.sbom_package.set_name(package)
            self.sbom_package.set_version(version)
            self.sbom_package.set_filesanalysis(False)
            license = self.license.find_license(self.get("License"))
            # Report license as reported by metadata. If not valid SPDX, report NOASSERTION
            if license != self.get("License"):
                self.sbom_package.set_licensedeclared("NOASSERTION")
            else:
                self.sbom_package.set_licensedeclared(license)
            # Report license if valid SPDX identifier
            self.sbom_package.set_licenseconcluded(license)
            # Add comment if metadata license was modified
            if len(self.get("License")) > 0 and license != self.get("License"):
                self.sbom_package.set_licensecomments(
                    f"{self.get('Name')} declares {self.get('License')} which is not a valid SPDX License identifier or expression."
                )
            supplier = self.get("Packager")
            if len(supplier.split()) > 3:
                self.sbom_package.set_supplier(
                    "Organization", self.format_supplier(supplier)
                )
            elif len(supplier) > 1:
                self.sbom_package.set_supplier("Person", self.format_supplier(supplier))
            else:
                self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
            if self.get("Summary") != "":
                self.sbom_package.set_summary(self.get("Summary"))
            if self.get("URL") != "":
                self.sbom_package.set_homepage(self.get("URL"))
            # Store package data
            self.sbom_packages[
                (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
            ] = self.sbom_package.get_package()
            # Add relationship
            self.sbom_relationship.initialise()
            if parent != "-":
                self.sbom_relationship.set_relationship(
                    parent, "DEPENDS_ON", package
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
                dependency = r.strip()
                if len(dependency) > 0 and self.process_package(dependency, parent):
                    self.analyze(dependency.strip(), self.get("Depends"))

    def process_distro_package(self, module_name):
        self.parent = f"{self.name}-{self.release}-Package-{module_name}"
        if self.process_package(module_name):
            self.analyze(self.get("Name"), self.get("Depends"))
