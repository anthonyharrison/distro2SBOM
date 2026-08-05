# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import re
from datetime import datetime, timezone
from pathlib import Path

from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner

from distro2sbom.distrobuilder.distrobuilder import DistroBuilder

# Location of the apk installed database, relative to the distribution root.
APK_DATABASE = "lib/apk/db/installed"

# Default namespace used within PURLs when the distribution cannot be identified.
DEFAULT_NAMESPACE = "alpine"

# Package level fields of a record within the apk installed database.
# See https://wiki.alpinelinux.org/wiki/Apk_spec
PACKAGE_FIELDS = {
    "P": "name",
    "V": "version",
    "A": "arch",
    "T": "description",
    "U": "url",
    "L": "license",
    "o": "origin",
    "m": "maintainer",
    "t": "build_time",
    "I": "size",
    "D": "depends",
    "p": "provides",
}

# Fields which describe the files owned by a package. These follow the package
# level fields within a record and mark the end of the package metadata.
FILE_FIELDS = {"F", "M", "R", "a", "Z"}

# Dependencies and provided names may carry a version constraint, e.g.
# 'libcrypto3=3.3.7-r0' or 'so:libssl.so.3=3'.
CONSTRAINT = re.compile(r"[<>=~]")

# A package identity of the form <name>-<pkgver>-r<pkgrel>. An Alpine pkgver
# never contains a hyphen, so anchoring on the trailing '-r<n>' makes the split
# between the name and the version unambiguous.
PACKAGE_IDENTITY = re.compile(r"^(?P<name>.+)-(?P<version>[^-\s]+-r\d+)$")

# An architecture as reported by 'apk list --installed', e.g. x86_64 or noarch.
ARCHITECTURE = re.compile(r"^[A-Za-z0-9_]+$")


class ApkBuilder(DistroBuilder):
    def __init__(self, name, release, debug=False, root="", namespace=""):
        super().__init__(debug, ecosystem="apk")
        self.sbom_package = SBOMPackage()
        self.sbom_relationship = SBOMRelationship()
        self.license = LicenseScanner()
        self.distro_packages = []
        self.set_namespace(namespace)
        if root != "":
            self.root = root
        self.system_data = self.get_system()
        if name is None and release is None:
            self.name = self.system_data.get("name", "Alpine Linux").replace(" ", "-")
            self.release = self.system_data.get("version_id", "NOASSERTION")
            if self.get_namespace() is None:
                self.set_namespace(self.system_data.get("id", ""))
        else:
            self.name = name.replace(" ", "-")
            self.release = release
        # A namespace is always required to generate a valid apk PURL
        if self.get_namespace() is None:
            self.set_namespace(DEFAULT_NAMESPACE)
        self.parent = f"Distro-{self.name}"
        # The distro qualifier of a PURL identifies the release which the
        # package was built for, e.g. 'alpine-3.20'.
        self.distro = f"{self.get_namespace()[:-1]}-{self.get_release_series()}"
        self.packages = {}
        self.provides = {}

    def get_release_series(self):
        # Alpine releases are identified by their major.minor version. The
        # patch level identifies the point release and is not part of the
        # repository identity.
        series = str(self.release).split(".")
        if len(series) > 2 and all(part.isdigit() for part in series[:2]):
            return ".".join(series[:2])
        return self.release

    #
    # Parsing of the apk installed database
    #

    def parse_database(self, lines):
        """Extract the package level metadata from an apk installed database."""
        packages = {}
        record = {}
        in_file_list = False
        for line in lines:
            entry = line.rstrip("\n")
            if entry.strip() == "":
                # A blank line terminates the record for a package
                self.store_record(record, packages)
                record = {}
                in_file_list = False
                continue
            # Every field is of the form <single character key>:<value>
            if len(entry) < 2 or entry[1] != ":":
                continue
            key, value = entry[0], entry[2:]
            if key in FILE_FIELDS:
                in_file_list = True
                continue
            if in_file_list:
                # Ignore anything which follows the list of files
                continue
            field = PACKAGE_FIELDS.get(key)
            # Only the first occurrence of a field is significant
            if field is not None and field not in record:
                record[field] = value
        # Handle a database which does not end with a blank line
        self.store_record(record, packages)
        return packages

    def store_record(self, record, packages):
        name = record.get("name", "")
        if name != "":
            packages[name] = record

    def get_database(self):
        """Read the package metadata for the installed distribution."""
        database = Path(f"{self.root}/{APK_DATABASE}")
        # Check path exists and is a valid file
        if not (database.exists() and database.is_file()):
            print(f"[ERROR] Unable to locate apk database {database}")
            return {}
        with open(database, encoding="utf-8", errors="replace") as db_file:
            packages = self.parse_database(db_file)
        if self.debug:
            print(f"{len(packages)} packages found in {database}")
        return packages

    def build_provides(self, packages):
        """Map each name which can satisfy a dependency to a package."""
        provides = {}
        # A package name always takes precedence over a provided name
        for name in packages:
            provides[name] = name
        for name, record in packages.items():
            for entry in record.get("provides", "").split():
                provided = self.strip_constraint(entry)
                if provided != "":
                    provides.setdefault(provided, name)
        return provides

    def strip_constraint(self, entry):
        # A dependency prefixed with '!' identifies a conflict rather than a
        # dependency and is therefore ignored.
        if entry == "" or entry.startswith("!"):
            return ""
        return CONSTRAINT.split(entry, 1)[0]

    def get_dependencies(self, package_name):
        """Report the installed packages which a package depends on."""
        record = self.packages.get(package_name, {})
        dependencies = []
        for entry in record.get("depends", "").split():
            dependency = self.provides.get(self.strip_constraint(entry))
            if dependency is None or dependency == package_name:
                # Either a dependency which is not installed or a package
                # which satisfies one of its own dependencies.
                continue
            if dependency not in dependencies:
                dependencies.append(dependency)
        return dependencies

    #
    # SBOM generation
    #

    def add_distribution(self, installed=True):
        """Add the component which represents the distribution itself.

        The metadata reported by the system is only used when reporting on the
        installed distribution. When processing a file containing the list of
        installed packages, the distribution being described is not necessarily
        the one which the tool is running on.
        """
        distro_root = self.name.lower().replace("_", "-")
        self.sbom_package.initialise()
        self.sbom_package.set_name(distro_root)
        self.sbom_package.set_version(self.release)
        self.sbom_package.set_type("operating-system")
        self.sbom_package.set_filesanalysis(False)
        license = "NOASSERTION"
        self.sbom_package.set_licensedeclared(license)
        self.sbom_package.set_licenseconcluded(license)
        if installed and self.system_data.get("home_url") is not None:
            self.sbom_package.set_homepage(self.system_data.get("home_url"))
        if installed and self.system_data.get("id") is not None:
            self.sbom_package.set_supplier("Organisation", self.system_data.get("id"))
        else:
            self.sbom_package.set_supplier("Organisation", self.get_namespace()[:-1])
        # Store package data
        self.sbom_packages[
            (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
        ] = self.sbom_package.get_package()
        self.sbom_relationship.initialise()
        self.sbom_relationship.set_relationship(self.parent, "DESCRIBES", distro_root)
        self.sbom_relationships.append(self.sbom_relationship.get_relationship())
        return distro_root

    def add_relationship(self, source, target):
        self.sbom_relationship.initialise()
        self.sbom_relationship.set_relationship(source.lower(), "DEPENDS_ON", target)
        self.sbom_relationships.append(self.sbom_relationship.get_relationship())

    def invalid_license(self, license_text):
        return (
            f"{self.sbom_package.get_name()} declares {license_text} which is "
            "not currently a valid SPDX License identifier or expression."
        )

    def set_license(self, license_text):
        license = self.license.find_license(license_text)
        # Report the license as declared by the metadata. If it is not a valid
        # SPDX identifier or expression, report NOASSERTION.
        if license != license_text:
            self.sbom_package.set_licensedeclared("NOASSERTION")
        else:
            self.sbom_package.set_licensedeclared(license)
        self.sbom_package.set_licenseconcluded(license)
        if license != "NOASSERTION":
            license_comment = (
                "This information was automatically extracted from the package."
            )
            if license_text != "NOASSERTION" and license != license_text:
                license_comment = (
                    f"{license_comment} {self.invalid_license(license_text)}"
                )
            if self.license.deprecated(license):
                license_comment = f"{license_comment} {license} is now deprecated."
            self.sbom_package.set_licensecomments(license_comment)
        elif license_text not in ["", "NOASSERTION"]:
            self.sbom_package.set_licensecomments(self.invalid_license(license_text))

    def set_supplier(self, maintainer):
        if len(maintainer.split()) > 3:
            self.sbom_package.set_supplier(
                "Organization", self.format_supplier(maintainer)
            )
        elif len(maintainer) > 1:
            self.sbom_package.set_supplier("Person", self.format_supplier(maintainer))
        else:
            self.sbom_package.set_supplier("UNKNOWN", "NOASSERTION")

    def get_build_date(self, build_time):
        # The build time is recorded as seconds since the epoch (UTC)
        if not build_time.isdigit():
            return ""
        return datetime.fromtimestamp(int(build_time), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    def component_name(self, package_name):
        """Report the name used for a package within the SBOM."""
        return package_name.lower().replace("_", "-")

    def add_package(self, record, parent="-"):
        """Add a component to the SBOM from an installed database record."""
        package = self.component_name(record.get("name", ""))
        version = record.get("version", "")
        self.sbom_package.initialise()
        self.sbom_package.set_name(package)
        self.sbom_package.set_version(version)
        if parent == "-":
            self.sbom_package.set_type("application")
        self.sbom_package.set_filesanalysis(False)
        self.set_license(record.get("license", "NOASSERTION"))
        self.set_supplier(record.get("maintainer", ""))
        if record.get("description", "") != "":
            self.sbom_package.set_summary(record["description"])
        if record.get("url", "") != "":
            self.sbom_package.set_homepage(record["url"])
        # The PURL reports the package name as recorded by apk. Only the case is
        # normalised (as required by the PURL specification) so that the
        # identifier continues to match the package within the repository.
        self.sbom_package.set_purl(
            self.get_purl(
                record.get("name", "").lower(),
                version,
                record.get("arch", ""),
                self.distro,
            )
        )
        # A CPE is deliberately not generated. The maintainer of an Alpine
        # package is an individual rather than the vendor of the software, so a
        # CPE derived from the package metadata would not match the entries
        # published for the component and would give a false sense of coverage.
        # The PURL is the accurate identifier for an apk package.
        build_date = self.get_build_date(record.get("build_time", ""))
        if build_date != "":
            self.sbom_package.set_value("build_date", build_date)
        if record.get("size", "") != "":
            self.sbom_package.set_property("filesize", record["size"])
        # The origin identifies the source package which the package was built
        # from. Several packages are commonly built from a single origin.
        if record.get("origin", "") != "":
            self.sbom_package.set_property("origin", record["origin"])
        # Store package data
        self.sbom_packages[
            (self.sbom_package.get_name(), self.sbom_package.get_value("version"))
        ] = self.sbom_package.get_package()
        # Add relationship
        if parent != "-":
            self.add_relationship(parent, package)
        else:
            self.sbom_relationship.initialise()
            self.sbom_relationship.set_relationship(self.parent, "DESCRIBES", package)
            self.sbom_relationships.append(self.sbom_relationship.get_relationship())

    def process_package(self, package_name, parent="-"):
        if self.debug:
            print(f"Process package {package_name}. Parent {parent}")
        # A dependency may be specified using a name which the package provides
        # rather than the name of the package itself.
        package_name = self.provides.get(package_name, package_name)
        # Check if we have already processed this package
        if package_name in self.distro_packages:
            self.add_relationship(parent, self.component_name(package_name))
            return 0
        record = self.packages.get(package_name)
        if record is None:
            if self.debug:
                print(f"Package {package_name} not found")
            return False
        self.distro_packages.append(package_name)
        self.add_package(record, parent)
        return True

    def analyze(self, parent, dependencies):
        # Relationships refer to a package using the name of the component
        # which represents it within the SBOM.
        parent_component = self.component_name(parent)
        for dependency in dependencies:
            if self.process_package(dependency, parent_component):
                self.analyze(dependency, self.get_dependencies(dependency))

    def load(self):
        self.packages = self.get_database()
        self.provides = self.build_provides(self.packages)
        return len(self.packages) > 0

    def process_distro_package(self, module_name):
        self.parent = f"{self.name}-{self.release}-Package-{module_name}"
        if not self.load():
            return
        if self.process_package(module_name):
            self.analyze(module_name, self.get_dependencies(module_name))

    def process_system(self):
        if not self.load():
            return
        distro_root = self.add_distribution()
        for module_name in self.packages:
            if self.debug:
                print(f"Processing... {module_name}")
            if self.process_package(module_name, distro_root):
                self.analyze(module_name, self.get_dependencies(module_name))

    #
    # Processing of a file containing the list of installed packages
    #

    def parse_data(self, filename):
        # Process file containing installed applications
        with open(filename, encoding="utf-8", errors="replace") as dir_file:
            lines = dir_file.readlines()
        if len(lines) == 0:
            return
        # Something to process
        distro_root = self.add_distribution(installed=False)
        for line in lines:
            record = self.parse_package_entry(line)
            if record is None:
                continue
            package = self.component_name(record["name"])
            if (package, record["version"]) in self.sbom_packages:
                continue
            self.add_package(record, distro_root)

    def parse_package_entry(self, line):
        """Parse a line reported by 'apk list --installed' or 'apk info -v'."""
        line_element = line.strip().split()
        if len(line_element) == 0:
            return None
        identity = PACKAGE_IDENTITY.match(line_element[0])
        if identity is None:
            # Not a package identity, e.g. a warning reported by apk
            return None
        record = {
            "name": identity.group("name"),
            "version": identity.group("version"),
        }
        # 'apk list --installed' reports additional metadata for each package
        # in the form '<identity> <arch> {<origin>} (<license>) [installed]'.
        if len(line_element) > 1 and ARCHITECTURE.match(line_element[1]):
            record["arch"] = line_element[1]
        remainder = " ".join(line_element[2:])
        origin = re.search(r"\{([^}]*)\}", remainder)
        if origin is not None:
            record["origin"] = origin.group(1)
        license = re.search(r"\(([^)]*)\)", remainder)
        if license is not None:
            record["license"] = license.group(1)
        return record
