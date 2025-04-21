# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import re
from pathlib import Path

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner

from distro2sbom.distrobuilder.distrobuilder import DistroBuilder


class DpkgBuilder(DistroBuilder):
    def __init__(self, name, release, debug=False, root="", namespace=""):
        super().__init__(debug, ecosystem="deb")
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.license = LicenseScanner()
        self.distro_packages = []
        self.set_namespace(namespace)
        self.system_data = self.get_system()
        if name is None and release is None:
            self.name = self.system_data["name"].replace(" ", "-")
            self.release = self.system_data["version_id"]
            self.distro = self.system_data.get("version_codename")
        else:
            self.name = name.replace(" ", "-")
            self.release = release
            self.distro = self.get_namespace()
        self.parent = f"Distro-{self.name}"
        self.root = root
        self.recommends = {}

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
            self.sbom_package.set_licenseconcluded(license)
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
                    if ":" in package:
                        package, architecture = package.split(":", 1)
                    else:
                        architecture = line_element[2]
                    self.sbom_package.set_purl(
                        self.get_purl(
                            package,
                            version,
                            architecture,
                            self.distro[:-1] if self.distro is not None else None,
                        )
                    )
                    self.sbom_package.set_name(package)
                    self.sbom_package.set_version(version)
                    self.sbom_package.set_type("application")
                    self.sbom_package.set_filesanalysis(False)
                    license = "NOASSERTION"
                    self.sbom_package.set_licensedeclared(license)
                    self.sbom_package.set_licenseconcluded(license)
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

    def get_metadata_from_file(self, package):
        # Location of Debian copyright files
        base_file = f"{self.root}/usr/share/doc/{package}/copyright"
        copyright_text = ""
        license_text = "NOASSERTION"
        filename = Path(base_file)
        # Check path exists and is a valid file
        if filename.exists() and filename.is_file():
            with open(filename, "r", errors="replace") as f:
                lines = f.readlines()
                copyright_found = False
                license_found = False
                for line in lines:
                    # Search for first Copyright and License statements
                    if copyright_found:
                        copyright_info = line.strip().rstrip("\n")
                        if len(copyright_info) > 0:
                            copyright_text = "Copyright: " + copyright_info
                            copyright_found = False
                    elif line.startswith("Copyright:") and len(copyright_text) == 0:
                        copyright_text = line.strip().rstrip("\n")
                        if len(copyright_text) <= len("Copyright:"):
                            # Assume copyright is on a following line
                            copyright_found = True
                    elif line.startswith("License:") and not license_found:
                        license_info = line.split("License:", 1)[1].strip().rstrip("\n")
                        if len(license_info) > 0:
                            license_text = license_info
                            license_found = True
        return license_text, copyright_text

    def dpkg_command(self, command_string):
        command = "dpkg"
        if self.root != "":
            command = f"{command} --root {self.root}"
        return self.run_program(f"{command} {command_string}")

    def process_package(self, package_name, parent="-"):
        self.set_namespace(self.system_data.get("id"))
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
        out = self.dpkg_command(f"-s {package_name}")
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
            if len(package) == 0:
                print(f"error with {package_name} processing")
            self.sbom_package.set_name(package)
            self.sbom_package.set_version(version)
            if parent == "-":
                self.sbom_package.set_type("application")
            self.sbom_package.set_filesanalysis(False)
            license_text, copyright = self.get_metadata_from_file(package_name)
            license = self.license.find_license(license_text)
            self.sbom_package.set_licensedeclared(license)
            self.sbom_package.set_licenseconcluded(license)
            if license != "NOASSERTION":
                license_comment = (
                    "This information was automatically extracted from the package."
                )
                if license_text != "NOASSERTION" and license != license_text:
                    self.sbom_package.set_licensedeclared("NOASSERTION")
                    license_comment = f"{license_comment} {self.sbom_package.get_name()} declares {license_text} which is not currently a valid SPDX License identifier or expression."
                if self.license.deprecated(license):
                    license_comment = f"{license_comment} {license} is now deprecated."
                self.sbom_package.set_licensecomments(license_comment)
            elif license_text != "NOASSERTION":
                license_comment = f"{self.sbom_package.get_name()} declares {license_text} which is not currently a valid SPDX License identifier or expression."
                if self.license.deprecated(license):
                    license_comment = f"{license_comment} {license} is now deprecated."
                self.sbom_package.set_licensecomments(license_comment)
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
            # Add copyright information
            if len(copyright) > 0:
                self.sbom_package.set_copyrighttext(copyright)
            self.sbom_package.set_purl(
                self.get_purl(package, version, self.get("Architecture"), self.distro)
            )
            if len(supplier) > 1:
                component_supplier = self.format_supplier(supplier, include_email=False)
                cpe_version = version.replace(":", "\\:")
                self.sbom_package.set_cpe(
                    f"cpe:2.3:a:{component_supplier.replace(' ', '_').lower()}:{package}:{cpe_version}:*:*:*:*:*:*:*"
                )
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
            # Remember recommends packages
            if self.get("Recommends") != "":
                self.recommends[package] = self.get("Recommends")
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

    def process_system(self):
        distro_root = self.name.lower().replace("_", "-")
        self.sbom_package.initialise()
        self.sbom_package.set_name(distro_root)
        self.sbom_package.set_version(self.release)
        self.sbom_package.set_type("operating-system")
        self.sbom_package.set_filesanalysis(False)
        license = "NOASSERTION"
        self.sbom_package.set_licensedeclared(license)
        self.sbom_package.set_licenseconcluded(license)
        if self.system_data.get("home_url") is not None:
            self.sbom_package.set_homepage(self.system_data.get("home_url"))
        if self.system_data.get("id") is not None:
            self.sbom_package.set_supplier("Organisation", self.system_data.get("id"))
        else:
            self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
        # Store package data
        self.sbom_packages[
            (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
        ] = self.sbom_package.get_package()
        self.sbom_relationship.initialise()
        self.sbom_relationship.set_relationship(self.parent, "DESCRIBES", distro_root)
        self.sbom_relationships.append(self.sbom_relationship.get_relationship())
        # Get installed packages
        out = self.dpkg_command("-l")
        for line in out:
            if line[:2] == "ii":
                # For each installed package
                line_element = re.sub(" +", " ", line[2:].strip().rstrip("\n")).split(
                    " "
                )
                module_name = line_element[0]
                if self.debug:
                    print(f"Processing... {module_name}")
                if self.process_package(module_name, distro_root):
                    self.analyze(self.get("Package"), self.get("Depends"))
        self.process_recommends()

    def process_recommends(self):
        # Add additional dependencies if recommended packages are installed
        for package, extra_packages in self.recommends.items():
            extra_dependent_packages = extra_packages.replace("|",",")
            for r in extra_dependent_packages.split(","):
                # Remove any version string information
                dependency = r.strip().split(" ")[0].replace(":any", "")
                if self.debug:
                    print (f"Check if {dependency} included. {dependency in self.distro_packages}")
                # if dependency installed, then add extra relationship
                if dependency in self.distro_packages:
                    if self.debug:
                        print (f"Add relationship from {package} to {dependency}")
                    self.sbom_relationship.initialise()
                    self.sbom_relationship.set_relationship(
                        package.lower(), "DEPENDS_ON", dependency
                    )
                    self.sbom_relationships.append(self.sbom_relationship.get_relationship())
