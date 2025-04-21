# Copyright (C) 2023 Anthony Harrison
# Copyright (C) 2025 Lucas Holt
# SPDX-License-Identifier: Apache-2.0

import os

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
                self.sbom_package.set_supplier("Organisation", "freebsd")
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
                        arch = self.get_arch(arch)
                        arch_component = f"&arch={arch}"
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
                        f"pkg:generic/{package}@{version}?distro=freebsd{arch_component}"
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

    def get_arch(self, arch_string):
        parts = arch_string.lower().split(":")
        if len(parts) != 3:
            return ""

        arch = parts[2]  # The architecture is the third part

        arch_map = {
            "i386": "x86",
            "amd64": "x86_64",
            "armv6": "armv6",
            "armv7": "armv7",
            "aarch64": "aarch64",
            "powerpc": "ppc",
            "mips": "mips",
            "sparc64": "sparc",
            "riscv": "riscv",
            "*": "*",  # architecture independent package
        }

        return arch_map.get(arch, arch)

    def get(self, attribute):
        if attribute in self.metadata:
            return self.metadata[attribute].lstrip()
        return ""

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
            package = self.get("Name").lower().replace("_", "-")
            version = self.get("Version")
            if len(package) == 0:
                print(f"error with {package_name} processing")
            self.sbom_package.initialise()
            self.sbom_package.set_name(package)
            self.sbom_package.set_version(version)
            if parent == "-":
                self.sbom_package.set_type("application")
            self.sbom_package.set_filesanalysis(False)

            license = self.get_licenses(package_name)
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
            if self.get("Comment") != "":
                self.sbom_package.set_summary(self.get("Comment"))
            if self.get("WWW") != "":
                self.sbom_package.set_homepage(self.get("WWW"))
            arch_component = self.get_arch(self.get("Architecture"))
            if len(arch_component) > 0:
                arch_component = f"&arch={arch_component}"
            self.sbom_package.set_purl(
                f"pkg:generic/{package}@{version}?distro=freebsd{arch_component}"
            )
            if len(supplier) > 1:
                component_supplier = "freebsd"
                # self.format_supplier(supplier, include_email=False)
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
            dependency = dependency.split(">")[0].split("<")[0].split("=")[0].strip()
            if dependency and self.process_package(dependency, parent):
                # Recursively get dependencies for this package
                sub_dependencies = self.pkg_command(f"info -d {dependency}")
                self.analyze(dependency, " ".join(sub_dependencies))

    def process_distro_package(self, module_name):
        self.parent = f"{self.name}-{self.release}-Package-{module_name}"
        if self.process_package(module_name):
            self.analyze(self.get("Package"), self.get("Depends"))

    def get_licenses(self, product):
        LICENSE_BASE = "/usr/local/share/licenses/"
        directory_path = f"{LICENSE_BASE}{product}"
        licenses = []
        ignore = ["LICENSE", "catalog.mk"]
        if os.path.isdir(directory_path):
            for entry in os.listdir(directory_path):
                if os.path.isfile(os.path.join(directory_path, entry)):
                    if entry not in ignore:
                        licenses.append(self.translate_license_to_spdx(entry))
        if len(licenses) == 0:
            return "NOASSERTION"

        # Assume licenses are any of.
        # Return SPDX license expression
        return " OR ".join(licenses)

    def translate_license_to_spdx(self, freebsd_license):
        # Common FreeBSD license translations
        license_map = {
            "BSD0CLAUSE": "0BSD",
            "BSD1CLAUSE": "BSD-1-Clause",
            "BSD2CLAUSE": "BSD-2-Clause",
            "BSD3CLAUSE": "BSD-3-Clause",
            "BSD4CLAUSE": "BSD-4-Clause",
            "MIT": "MIT",
            "APACHE10": "Apache-1.0",
            "APACHE11": "Apache-1.1",
            "APACHE20": "Apache-2.0",
            "GPLv1": "GPL-1.0-only",
            "GPLv1+": "GPL-1.0-or-later",
            "GPLv2": "GPL-2.0-only",
            "GPLv2+": "GPL-2.0-or-later",
            "GPLv3": "GPL-3.0-only",
            "GPLv3+": "GPL-3.0-or-later",
            "GPLv3RLE": "GPL-3.0-with-GCC-exception",
            "GPLv3RLE+": "GPL-3.0-or-later-with-GCC-exception",
            "AGPLv3": "AGPL-3.0-only",
            "AGPLv3+": "AGPL-3.0-or-later",
            "LGPL20": "LGPL-2.0-only",
            "LGPL20+": "LGPL-2.0-or-later",
            "LGPL21": "LGPL-2.1-only",
            "LGPL21+": "LGPL-2.1-or-later",
            "LGPL3": "LGPL-3.0-only",
            "LGPL3+": "LGPL-3.0-or-later",
            "MPL11": "MPL-1.1",
            "MPL20": "MPL-2.0",
            "CDDL": "CDDL-1.0",
            "ZLIB": "Zlib",
            "ISC": "ISC",
            "POSTGRESQL": "PostgreSQL",
            "ARTISTIC": "Artistic-1.0-Perl",
            "ARTISTIC2": "Artistic-2.0",
            "PHP202": "PHP-2.02",
            "PHP30": "PHP-3.0",
            "PHP301": "PHP-3.01",
            "UNLICENSE": "Unlicense",
            "OPENSSL": "OpenSSL",
            "PSFL": "Python-2.0",
            "RUBY": "Ruby",
        }

        # Remove common suffixes and convert to uppercase
        cleaned_license = (
            freebsd_license.upper().replace("LICENSE", "").replace(".TXT", "").strip()
        )

        # Check if the cleaned license is in our map
        if cleaned_license in license_map:
            return license_map[cleaned_license]

        # If not found in the map, return the original license name
        # This ensures we don't lose any license information we can't translate
        return freebsd_license

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
            self.sbom_package.set_supplier("Organisation", "freebsd")
        self.sbom_packages[
            (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
        ] = self.sbom_package.get_package()
        self.sbom_relationship.initialise()
        self.sbom_relationship.set_relationship(self.parent, "DESCRIBES", distro_root)
        self.sbom_relationships.append(self.sbom_relationship.get_relationship())
        # Get installed packages
        out = self.pkg_command("query %n:%v")
        for line in out:
            if ":" in line:
                package_info = line.split(":", 1)
                if len(package_info) == 2:
                    module_name = package_info[0].strip()
                    if self.debug:
                        print(f"Processing... {module_name}")
                    if self.process_package(module_name, distro_root):
                        dependencies = self.pkg_command(f"info -d {module_name}")
                        self.analyze(module_name, " ".join(dependencies))
