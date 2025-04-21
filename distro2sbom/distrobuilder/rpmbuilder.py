# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner

from distro2sbom.distrobuilder.distrobuilder import DistroBuilder


class RpmBuilder(DistroBuilder):
    def __init__(self, name, release, debug=False, namespace=""):
        super().__init__(debug, ecosystem="rpm")
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
        self.rpm_options = os.environ.get("DISTRO2SBOM_RPM_OPTIONS", "")
        self.yum_options = os.environ.get("DISTRO2SBOM_YUM_OPTIONS", "")

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
                line_element = line.strip().rstrip("\n")
                # Typical line is accountsservice-libs-0.6.55-10.el9.x86_64
                # Package Name = accountsservice-libs
                # Version = 0.6.55-10.el9
                # Architecture = x86_64
                # Extract the package name (without extension) - make lowercase
                item = os.path.splitext(os.path.basename(line_element))[0].lower()
                # Parse line PRODUCT-VERSION[-Other]?. If pattern not followed ignore...
                # Version assumed to start with digit.
                product_version = re.search(r"-\d[.\d]*[a-z0-9]*", item)
                # This will include the architecture component
                product_release = line_element.split("-")[-1]
                # Extract architecture from last element
                architecture = line_element.split(".")[-1]
                # Remove architecture component
                product_release = product_release.replace(f".{architecture}", "")
                if product_version is not None:
                    # Find package name
                    package = item[: product_version.start()].lower().replace("_", "-")
                    self.sbom_package.initialise()
                    version = f"{product_version.group(0)[1:]}-{product_release}"
                    self.sbom_package.set_name(package)
                    self.sbom_package.set_version(version)
                    self.sbom_package.set_type("application")
                    self.sbom_package.set_filesanalysis(False)
                    license = "NOASSERTION"
                    self.sbom_package.set_licensedeclared(license)
                    self.sbom_package.set_licenseconcluded(license)
                    self.sbom_package.set_purl(
                        self.get_purl(
                            package,
                            version,
                            architecture,
                            self.distro[:-1] if self.distro is not None else None,
                        )
                    )
                    self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")
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
        self.set_namespace(self.system_data.get("id"))
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
        out = self.run_program(f"rpm {self.rpm_options} -qi {package_name}")
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
                f"yum repoquery {self.yum_options} --deplist {package_name}"
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
            if self.get("Release") != "":
                version = f'{version}-{self.get("Release")}'
            if parent == "-":
                self.sbom_package.set_type("application")
            self.sbom_package.set_name(package)
            self.sbom_package.set_version(version)
            self.sbom_package.set_filesanalysis(False)
            license_text = self.get("License")
            license = self.license.find_license(license_text)
            # Report license as reported by metadata. If not valid SPDX, report NOASSERTION
            if license != license_text:
                self.sbom_package.set_licensedeclared("NOASSERTION")
            else:
                self.sbom_package.set_licensedeclared(license)
            # Report license if valid SPDX identifier
            self.sbom_package.set_licenseconcluded(license)
            if license != "NOASSERTION":
                license_comment = (
                    "This information was automatically extracted from the package."
                )
                if license_text != "NOASSERTION" and license != license_text:
                    license_comment = f"{license_comment} {self.sbom_package.get_name()} declares {license_text} which is not currently a valid SPDX License identifier or expression."
                if self.license.deprecated(license):
                    license_comment = f"{license_comment} {license} is now deprecated."
                self.sbom_package.set_licensecomments(license_comment)
            elif license_text != "NOASSERTION":
                license_comment = f"{self.sbom_package.get_name()} declares {license_text} which is not currently a valid SPDX License identifier or expression."
                if self.license.deprecated(license):
                    license_comment = f"{license_comment} {license} is now deprecated."
                self.sbom_package.set_licensecomments(license_comment)
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
            # External references
            self.sbom_package.set_purl(
                self.get_purl(
                    package,
                    version,
                    self.get("Architecture"),
                    self.distro[:-1] if self.distro is not None else None,
                )
            )
            if len(supplier) > 1:
                component_supplier = self.format_supplier(supplier, include_email=False)
                cpe_version = version.replace(":", "\\:")
                self.sbom_package.set_cpe(
                    f"cpe:2.3:a:{component_supplier.replace(' ', '_').lower()}:{package}:{cpe_version}:*:*:*:*:*:*:*"
                )
            if self.get("Build Date") != "":
                self.sbom_package.set_value("build_date", self.get("Build Date"))
            if self.get("Install Date") != "":
                self.sbom_package.set_value("release_date", self.get("Install Date"))
            if self.get("Size"):
                self.sbom_package.set_property("filesize", self.get("Size"))
            # Store package data
            self.sbom_packages[
                (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
            ] = self.sbom_package.get_package()
            # Add relationship
            self.sbom_relationship.initialise()
            if parent != "-":
                self.sbom_relationship.set_relationship(parent, "DEPENDS_ON", package)
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
        out = self.run_program(f"rpm {self.rpm_options} -qa")
        for line in out:
            # Parse line PRODUCT-VERSION[-Other]?. If pattern not followed ignore...
            item = os.path.splitext(os.path.basename(line.strip().rstrip("\n")))[
                0
            ].lower()
            # Find start of version so that product name can be found
            product_version = re.search(r"-\d[.\d]*[a-z0-9]*", item)
            if product_version is None:
                continue
            module_name = item[: product_version.start()].lower().replace("_", "-")
            if self.debug:
                print(f"Processing... {module_name}")
            if self.process_package(module_name, distro_root):
                self.analyze(self.get("Name"), self.get("Depends"))
