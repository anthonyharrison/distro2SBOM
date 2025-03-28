# Copyright (C) 2023 Anthony Harrison
# Copyright (C) 2025 Lucas Holt
# SPDX-License-Identifier: Apache-2.0

import re
from pathlib import Path

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner

from distro2sbom.distrobuilder.distrobuilder import DistroBuilder


class FreeBSDBuilder(DistroBuilder):
    def __init__(self, name, release, debug=False, root=""):
        super().__init__(debug)
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.license = LicenseScanner()
        self.distro_packages = []
        self.system_data = self.get_system()
        if name is None and release is None:
            self.name = self.system_data["name"].replace(" ", "-")
            self.release = self.system_data["version_id"]
        else:
            self.name = name.replace(" ", "-")
            self.release = release
        self.parent = f"Distro-{self.name}"
        self.root = root

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
            if self.system_data.get("id") is not None:
                self.sbom_package.set_supplier(
                    "Organisation", self.system_data.get("id")
                )
            else:
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
                line_element = line.strip().split()
                if len(line_element) >= 2:
                    package = line_element[0].lower().replace("_", "-")
                    version = line_element[1]
                    self.sbom_package.initialise()
                    if ":" in package:
                        package, arch = package.split(":", 1)
                        arch_component = f"?arch={arch}"
                    else:
                        arch_component = ""
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
                    self.sbom_package.set_purl(
                        f"pkg:freebsd/{self.get_namespace()}{package}@{version}{arch_component}"
                    )
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
        license_dir = f"{self.root}/usr/local/share/licenses"
        copyright_text = ""
        license_text = "NOASSERTION"

        package_dir = Path(license_dir) / package
        if not package_dir.exists():
            # Try to find a directory that starts with the package name (to handle versioned directories)
            matching_dirs = list(Path(license_dir).glob(f"{package}-*"))
            if matching_dirs:
                package_dir = matching_dirs[0]

        license_file = package_dir / "LICENSE"

        if license_file.exists() and license_file.is_file():
            with open(license_file, "r", errors="replace") as f:
                content = f.read()

                # Try to extract the license information
                single_license_match = re.search(r'This package has a single license: (.*?)\.', content)
                multiple_licenses_match = re.search(r'This package has multiple licenses \(all of\):(.*?)(?=\n\n|\Z)',
                                                    content, re.DOTALL)

                if single_license_match:
                    license_text = single_license_match.group(1).strip()
                elif multiple_licenses_match:
                    licenses = re.findall(r'- (\w+) \((.*?)\)', multiple_licenses_match.group(1))
                    license_text = " AND ".join([license[0] for license in licenses])
                else:
                    # If neither format is found, use the whole content as license text
                    license_text = content.strip()

                copyright_match = re.search(r'Copyright \(c\).*', content)
                if copyright_match:
                    copyright_text = copyright_match.group(0)

        return license_text, copyright_text

    def pkg_command(self, command_string):
        command = "pkg"
        if self.root != "":
            command = f"{command} --rootdir {self.root}"
        return self.run_program(f"{command} {command_string}")

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
        out = self.pkg_command(f"info {package_name}")
        # If package not found, no metadata returned
        if len(out) > 0:
            self.metadata = {}
            current_key = None
            for line in out:
                if ":" in line:
                    key, value = line.split(":", 1)
                    current_key = key.strip()
                    self.metadata[current_key] = value.strip()
                elif current_key:
                    self.metadata[current_key] += " " + line.strip()
            self.sbom_package.initialise()
            package = self.get("Name").lower().replace("_", "-")
            # Attempt to do a quick conversion on a few package prefixes in freebsd. (likely should be done more sophisticated)
            if package.startswith("p5-"):
                package = package.replace("p5-", "perl-").replace(":", "-")
            elif package.startswith("py"):
                # of the form py39-mymodule-foobar-1.2.3
                py_match = re.match(r'py(\d+)-(.*)', package)
                if py_match:
                    _, pkg_name = py_match.groups()
                    package = f"python-{pkg_name}"
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
            if self.get("Comment") != "":
                self.sbom_package.set_summary(self.get("Comment"))
            if self.get("WWW") != "":
                self.sbom_package.set_homepage(self.get("WWW"))
            # Add copyright information
            if len(copyright) > 0:
                self.sbom_package.set_copyrighttext(copyright)
            arch_component=self.get("Architecture")
            if len(arch_component)> 0:
                arch_component=f"?{arch_component}"
            self.sbom_package.set_purl(
                f"pkg:generic/{package}@{version}?distro=freebsd{arch_component}"
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
        elif self.debug:
            print(f"Package {package_name} not found")
        return len(out) > 0

    def analyze(self, parent, dependencies):
        if not dependencies:
            return
        for dependency in dependencies.split():
            # FreeBSD dependencies might include version requirements, strip them
            dependency = dependency.split('>')[0].split('<')[0].split('=')[0].strip()
            if dependency and self.process_package(dependency, parent):
                # Recursively get dependencies for this package
                sub_dependencies = self.pkg_command(f"info -d {dependency}")
                self.analyze(dependency, ' '.join(sub_dependencies))

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
        self.sbom_packages[
            (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
        ] = self.sbom_package.get_package()
        self.sbom_relationship.initialise()
        self.sbom_relationship.set_relationship(self.parent, "DESCRIBES", distro_root)
        self.sbom_relationships.append(self.sbom_relationship.get_relationship())
        # Get installed packages
        out = self.pkg_command("info -a")
        for line in out:
            if ':' in line:
                package_info = line.split(':', 1)
                if len(package_info) == 2:
                    module_name = package_info[0].strip()
                    if self.debug:
                        print(f"Processing... {module_name}")
                    if self.process_package(module_name, distro_root):
                        dependencies = self.pkg_command(f"info -d {module_name}")
                        self.analyze(module_name, ' '.join(dependencies))
