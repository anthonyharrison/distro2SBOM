# Copyright (C) 2026 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import pytest

from distro2sbom.distrobuilder.apkbuilder import ApkBuilder

# An extract from an apk installed database. The records exercise the
# dependency forms used by Alpine: a shared library (so:), a command (cmd:),
# a file path, a plain package name and a version constraint.
INSTALLED_DATABASE = """C:Q1qKcZ+j23xssAXmgQhkOO8dHnbWw=
P:alpine-baselayout
V:3.6.5-r0
A:x86_64
S:8515
I:315392
T:Alpine base dir structure and init scripts
U:https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout
L:GPL-2.0-only
o:alpine-baselayout
m:Natanael Copa <ncopa@alpinelinux.org>
t:1714981135
c:66187892e05b03a41d08e9acabd19b7576a1c875
D:alpine-baselayout-data=3.6.5-r0 /bin/sh
q:1000
F:etc
R:motd
Z:Q1SLkS9hBidUbPwwrw+XR0Whv3ww8=
F:etc/modprobe.d
R:aliases.conf
a:0:0:600
Z:Q1WUbh6TBYNVK7e4Y+uUvLs/7viqk=

C:Q1oGXBcNBP/4qNKZQmqLBNQNQpqEo=
P:alpine-baselayout-data
V:3.6.5-r0
A:x86_64
I:77824
T:Alpine base dir structure and init scripts
U:https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout
L:GPL-2.0-only
o:alpine-baselayout
m:Natanael Copa <ncopa@alpinelinux.org>
t:1714981135

C:Q10x0SiWGr7WTkprUc9El8xZKQq28=
P:busybox
V:1.36.1-r31
A:x86_64
I:929792
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Soeren Tempel <soeren+alpine@soeren-tempel.net>
t:1763908338
D:so:libc.musl-x86_64.so.1
p:cmd:busybox=1.36.1-r31
r:busybox-initscripts

C:Q1S8NnLWvJPJHAKZ2ZTSC5nHiPSSo=
P:busybox-binsh
V:1.36.1-r31
A:x86_64
I:8192
T:busybox ash /bin/sh
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Soeren Tempel <soeren+alpine@soeren-tempel.net>
t:1763908338
D:busybox=1.36.1-r31
p:/bin/sh cmd:sh=1.36.1-r31

C:Q1bTtF5526tETKfL+lnigzIDlF+Ik=
P:musl
V:1.2.5-r3
A:x86_64
I:667648
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Timo Teraes <timo.teras@iki.fi>
t:1775835485
p:so:libc.musl-x86_64.so.1=1

C:Q13U97ISgQ0qv5vX8tQHN+RsyxD5s=
P:musl-utils
V:1.2.5-r3
A:x86_64
I:131072
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT AND BSD-2-Clause AND GPL-2.0-or-later
o:musl
m:Timo Teraes <timo.teras@iki.fi>
t:1775835485
D:scanelf so:libc.musl-x86_64.so.1 !busybox
p:libc-utils=1.2.5-r3 cmd:getconf=1.2.5-r3
r:libiconv

C:Q1nQwGVfsIvJRnHJnUsQ8lMBqxmXo=
P:libc-utils
V:0.7.2-r5
A:x86_64
I:4096
T:Meta package to pull in correct libc
U:https://alpinelinux.org
L:BSD-2-Clause AND BSD-3-Clause
o:libc-dev
m:Natanael Copa <ncopa@alpinelinux.org>
t:1706205037
D:musl-utils

C:Q1Vu34l9NC4A0TeEg2VVRHPh6X3Og=
P:ssl_client
V:1.36.1-r31
A:x86_64
I:28672
T:EXternal ssl_client for busybox wget
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Soeren Tempel <soeren+alpine@soeren-tempel.net>
t:1763908338
D:so:libc.musl-x86_64.so.1
p:cmd:ssl_client=1.36.1-r31
"""

OS_RELEASE = """NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.10
PRETTY_NAME="Alpine Linux v3.20"
HOME_URL="https://alpinelinux.org/"
"""


@pytest.fixture
def distro_root(tmp_path):
    """A minimal Alpine root filesystem containing the apk metadata."""
    database = tmp_path / "lib" / "apk" / "db"
    database.mkdir(parents=True)
    (database / "installed").write_text(INSTALLED_DATABASE)
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "os-release").write_text(OS_RELEASE)
    return tmp_path


def build(root, name=None, release=None, namespace=""):
    return ApkBuilder(name, release, root=str(root), namespace=namespace)


class TestDatabaseParsing:
    def test_all_packages_are_reported(self, distro_root):
        builder = build(distro_root)
        packages = builder.get_database()
        assert sorted(packages) == [
            "alpine-baselayout",
            "alpine-baselayout-data",
            "busybox",
            "busybox-binsh",
            "libc-utils",
            "musl",
            "musl-utils",
            "ssl_client",
        ]

    def test_package_metadata_is_extracted(self, distro_root):
        builder = build(distro_root)
        record = builder.get_database()["busybox"]
        assert record["version"] == "1.36.1-r31"
        assert record["arch"] == "x86_64"
        assert record["license"] == "GPL-2.0-only"
        assert record["origin"] == "busybox"
        assert record["url"] == "https://busybox.net/"
        assert record["description"].startswith("Size optimized")

    def test_file_entries_are_not_treated_as_metadata(self, distro_root):
        # 'R:motd' and 'a:0:0:600' follow the package fields of the first
        # record and must not be mistaken for package metadata.
        builder = build(distro_root)
        record = builder.get_database()["alpine-baselayout"]
        assert "motd" not in record.values()
        assert record["depends"] == "alpine-baselayout-data=3.6.5-r0 /bin/sh"

    def test_metadata_cannot_be_injected_through_the_file_list(self, distro_root):
        # Anything which follows the list of files owned by a package is not
        # package metadata, even where it is well formed.
        builder = build(distro_root)
        packages = builder.parse_database(
            [
                "P:example\n",
                "V:1.0-r0\n",
                "F:etc\n",
                "R:passwd\n",
                "T:injected description\n",
                "L:injected-license\n",
                "D:injected-dependency\n",
            ]
        )
        assert packages["example"] == {"name": "example", "version": "1.0-r0"}

    def test_final_record_without_trailing_blank_line(self, distro_root):
        builder = build(distro_root)
        # musl-utils is the last record and the database has no trailing
        # blank line separating it from the end of the file.
        assert "musl-utils" in builder.get_database()

    def test_malformed_input_is_ignored(self, distro_root):
        builder = build(distro_root)
        packages = builder.parse_database(
            ["not a field\n", "P:example\n", "V:1.0-r0\n", "\n", "!!!\n"]
        )
        assert packages == {"example": {"name": "example", "version": "1.0-r0"}}

    def test_the_first_value_of_a_repeated_field_is_reported(self, distro_root):
        # A repeated field is reported deterministically so that a crafted
        # database cannot override the metadata for a package.
        builder = build(distro_root)
        packages = builder.parse_database(
            ["P:example\n", "V:1.0-r0\n", "L:MIT\n", "L:injected-license\n"]
        )
        assert packages["example"]["license"] == "MIT"

    def test_missing_database_is_reported(self, tmp_path):
        builder = ApkBuilder("Alpine Linux", "3.20.10", root=str(tmp_path))
        assert builder.get_database() == {}
        assert builder.get_packages() == {}


class TestDependencyResolution:
    def test_shared_library_dependency_resolves_to_package(self, distro_root):
        builder = build(distro_root)
        builder.load()
        # busybox depends on so:libc.musl-x86_64.so.1, provided by musl
        assert builder.get_dependencies("busybox") == ["musl"]

    def test_file_dependency_resolves_to_package(self, distro_root):
        builder = build(distro_root)
        builder.load()
        # alpine-baselayout depends on /bin/sh, provided by busybox-binsh
        assert builder.get_dependencies("alpine-baselayout") == [
            "alpine-baselayout-data",
            "busybox-binsh",
        ]

    def test_conflicts_and_uninstalled_dependencies_are_ignored(self, distro_root):
        builder = build(distro_root)
        builder.load()
        # '!busybox' declares a conflict with an installed package and must
        # not be reported as a dependency. 'scanelf' is not installed.
        assert builder.get_dependencies("musl-utils") == ["musl"]

    def test_version_constraints_are_stripped(self, distro_root):
        builder = build(distro_root)
        builder.load()
        assert builder.get_dependencies("busybox-binsh") == ["busybox"]

    def test_a_package_does_not_depend_on_itself(self, distro_root):
        # A package may declare a dependency which it satisfies itself. This
        # must not be reported as a relationship, which would be a cycle.
        builder = build(distro_root)
        builder.packages = builder.parse_database(
            ["P:example\n", "V:1.0-r0\n", "D:cmd:example\n", "p:cmd:example=1.0-r0\n"]
        )
        builder.provides = builder.build_provides(builder.packages)
        assert builder.get_dependencies("example") == []

    def test_a_package_name_takes_precedence_over_a_provided_name(self, distro_root):
        builder = build(distro_root)
        builder.load()
        assert builder.provides["busybox"] == "busybox"
        assert builder.provides["so:libc.musl-x86_64.so.1"] == "musl"
        assert builder.provides["/bin/sh"] == "busybox-binsh"
        # musl-utils provides 'libc-utils', but libc-utils is itself an
        # installed package and must be the one which is reported.
        assert builder.provides["libc-utils"] == "libc-utils"
        assert builder.get_dependencies("libc-utils") == ["musl-utils"]


class TestSystemSbom:
    def test_every_installed_package_is_reported(self, distro_root):
        builder = build(distro_root)
        builder.process_system()
        # The eight packages plus the component for the distribution itself
        assert len(builder.get_packages()) == 9

    def test_purl_identifies_the_package_within_the_release(self, distro_root):
        builder = build(distro_root)
        builder.process_system()
        package = builder.get_packages()[("busybox", "1.36.1-r31")]
        assert (
            package["externalreference"][0][2]
            == "pkg:apk/alpine/busybox@1.36.1-r31?arch=x86_64&distro=alpine-3.20"
        )

    def test_licenses_are_reported(self, distro_root):
        builder = build(distro_root)
        builder.process_system()
        packages = builder.get_packages()
        assert packages[("busybox", "1.36.1-r31")]["licenseconcluded"] == "GPL-2.0-only"
        # A compound SPDX expression is reported unchanged
        assert (
            packages[("musl-utils", "1.2.5-r3")]["licenseconcluded"]
            == "MIT AND BSD-2-Clause AND GPL-2.0-or-later"
        )

    def test_no_cpe_is_generated_from_the_maintainer(self, distro_root):
        # A CPE built from the maintainer would not match the entries
        # published for the component, so none is reported.
        builder = build(distro_root)
        builder.process_system()
        for package in builder.get_packages().values():
            assert "cpe" not in package

    def test_dependencies_are_reported_as_relationships(self, distro_root):
        builder = build(distro_root)
        builder.process_system()
        relationships = {
            (r["source"], r["type"], r["target"]) for r in builder.get_relationships()
        }
        assert ("busybox", "DEPENDS_ON", "musl") in relationships
        assert ("alpine-baselayout", "DEPENDS_ON", "busybox-binsh") in relationships
        assert ("Distro-Alpine-Linux", "DESCRIBES", "alpine-linux") in relationships

    def test_the_purl_reports_the_name_recorded_by_apk(self, distro_root):
        # The component name is normalised for use as an identifier, but the
        # PURL must continue to identify the package within the repository.
        builder = build(distro_root)
        builder.process_system()
        package = builder.get_packages()[("ssl-client", "1.36.1-r31")]
        assert package["externalreference"][0][2].startswith(
            "pkg:apk/alpine/ssl_client@1.36.1-r31"
        )

    def test_every_relationship_refers_to_a_reported_component(self, distro_root):
        # A package whose name contains an underscore is reported using a
        # normalised name. Relationships must use the same name, otherwise
        # the dependency is lost when the SBOM is generated.
        builder = build(distro_root)
        builder.process_system()
        components = {name for name, _ in builder.get_packages()}
        for relationship in builder.get_relationships():
            if relationship["type"] != "DEPENDS_ON":
                continue
            assert relationship["source"] in components
            assert relationship["target"] in components

    def test_dependencies_of_a_normalised_package_are_reported(self, distro_root):
        builder = build(distro_root)
        builder.process_system()
        relationships = {
            (r["source"], r["target"]) for r in builder.get_relationships()
        }
        assert ("ssl-client", "musl") in relationships

    def test_build_date_is_reported_in_utc(self, distro_root):
        builder = build(distro_root)
        builder.process_system()
        package = builder.get_packages()[("busybox", "1.36.1-r31")]
        assert package["build_date"] == "2025-11-23T14:32:18Z"


class TestPackageSbom:
    def test_only_the_package_and_its_dependencies_are_reported(self, distro_root):
        builder = build(distro_root)
        builder.process_distro_package("busybox-binsh")
        assert sorted(name for name, _ in builder.get_packages()) == [
            "busybox",
            "busybox-binsh",
            "musl",
        ]

    def test_an_unknown_package_reports_nothing(self, distro_root):
        builder = build(distro_root)
        builder.process_distro_package("no-such-package")
        assert builder.get_packages() == {}


class TestPackageListParsing:
    @pytest.mark.parametrize(
        "line, name, version",
        [
            ("busybox-1.36.1-r31", "busybox", "1.36.1-r31"),
            ("py3-setuptools-70.3.0-r0", "py3-setuptools", "70.3.0-r0"),
            ("ssl_client-1.36.1-r31", "ssl_client", "1.36.1-r31"),
            (
                "ca-certificates-bundle-20240705-r0",
                "ca-certificates-bundle",
                "20240705-r0",
            ),
        ],
    )
    def test_a_package_identity_is_split_correctly(
        self, distro_root, line, name, version
    ):
        builder = build(distro_root)
        record = builder.parse_package_entry(line)
        assert record["name"] == name
        assert record["version"] == version

    def test_metadata_reported_by_apk_list_is_extracted(self, distro_root):
        builder = build(distro_root)
        record = builder.parse_package_entry(
            "musl-utils-1.2.5-r3 x86_64 {musl} (MIT AND BSD-2-Clause) [installed]"
        )
        assert record["name"] == "musl-utils"
        assert record["arch"] == "x86_64"
        assert record["origin"] == "musl"
        assert record["license"] == "MIT AND BSD-2-Clause"

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "   ",
            "WARNING: opening from cache https://dl-cdn.alpinelinux.org: No such file",
            "busybox",
        ],
    )
    def test_lines_which_are_not_a_package_are_ignored(self, distro_root, line):
        builder = build(distro_root)
        assert builder.parse_package_entry(line) is None

    def test_a_package_list_generates_an_sbom(self, distro_root, tmp_path):
        listing = tmp_path / "packages.out"
        listing.write_text(
            "WARNING: opening from cache: No such file or directory\n"
            "busybox-1.36.1-r31 x86_64 {busybox} (GPL-2.0-only) [installed]\n"
            "musl-1.2.5-r3 x86_64 {musl} (MIT) [installed]\n"
        )
        builder = build(distro_root, name="Alpine Linux", release="3.20.10")
        builder.parse_data(str(listing))
        assert sorted(name for name, _ in builder.get_packages()) == [
            "alpine-linux",
            "busybox",
            "musl",
        ]


class TestReleaseIdentity:
    @pytest.mark.parametrize(
        "release, series",
        [
            ("3.20.10", "3.20"),
            ("3.20", "3.20"),
            ("edge", "edge"),
            ("NOASSERTION", "NOASSERTION"),
        ],
    )
    def test_the_release_series_identifies_the_repository(
        self, distro_root, release, series
    ):
        builder = build(distro_root, name="Alpine Linux", release=release)
        assert builder.get_release_series() == series

    def test_the_namespace_can_be_overridden(self, distro_root):
        builder = build(distro_root, namespace="wolfi")
        builder.process_system()
        package = builder.get_packages()[("busybox", "1.36.1-r31")]
        assert package["externalreference"][0][2].startswith("pkg:apk/wolfi/busybox@")
