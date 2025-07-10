# DISTRO2SBOM

The DISTRO2SBOM generates a
SBOM (Software Bill of Materials) for either an installed application or a complete system installation in a number of formats including
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).
An SBOM for an installed package will identify all of its dependent components.

It is intended to be used as part of a continuous integration system to enable accurate records of SBOMs to be maintained
and also to support subsequent audit needs to determine if a particular component (and version) has been used.

## Installation

To install use the following command:

`pip install distro2sbom`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

## Usage

```
usage: distro2sbom [-h] [--distro {rpm,deb,windows,freebsd,auto}] [-i INPUT_FILE] [-n NAME] [-r RELEASE] [-p PACKAGE] [-s] [--root ROOT] [--distro-namespace DISTRO_NAMESPACE]
                   [--product-type {application,framework,library,container,operating-system,device,firmware,file}] [--product-name PRODUCT_NAME] [--product-version PRODUCT_VERSION]
                   [--product-author PRODUCT_AUTHOR] [-d] [--sbom {spdx,cyclonedx}] [--format {tag,json,yaml}] [-o OUTPUT_FILE] [-V]

Distro2Sbom generates a Software Bill of Materials for the specified package or distribution.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

Input:
  --distro {rpm,deb,windows,auto}
                        type of distribution (default: auto)
  -i INPUT_FILE, --input-file INPUT_FILE
                        name of distribution file
  -n NAME, --name NAME  name of distribution
  -r RELEASE, --release RELEASE
                        release identity of distribution
  -p PACKAGE, --package PACKAGE
                        identity of package within distribution
  -s, --system          generate SBOM for installed system
  --root ROOT           location of distribution packages
  --distro-namespace DISTRO_NAMESPACE
                        namespace for distribution

Product:
  --product-type {application,framework,library,container,operating-system,device,firmware,file}
                        type of product
  --product-name PRODUCT_NAME
                        name of product
  --product-version PRODUCT_VERSION
                        version of product
  --product-author PRODUCT_AUTHOR
                        author of product

Output:
  -d, --debug           add debug information
  --sbom {spdx,cyclonedx}
                        specify type of sbom to generate (default: spdx)
  --format {tag,json,yaml}
                        specify format of software bill of materials (sbom) (default: tag)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output filename (default: output to stdout)
```
						
## Operation

The `--distro` option is used to identify the type of distribution. The default option is auto which attempts to determine the type of distribution by searching for the
presence of key applications required by the tool. If none of the required applications are found, the tool terminates.

The `--name` option and `--release` option is used to identify the name and release of the distribution. Values for both options are required to be specified if the
`--input-file` option is used. If they are not specified, values for these options shall be obtained from system files installed on the system.

The `--input-file` option is used to provide a filename containing the list of packages installed on the system. The format of the file is dependent on the specified `--distro` option.

- deb. The file used is the output of the following command
    ```bash
    dpkg -l > [filename.out]
    ```

    Sample file contents
    ```console
  Desired=Unknown/Install/Remove/Purge/Hold
  | Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
  |/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
  ||/ Name                                             Version                             Architecture Description
  +++-================================================-===================================-============-==================================================================================
  ii  acl                                              2.3.1-1                             amd64        access control list - utilities
  ii  adduser                                          3.129                               all          add and remove users and groups
  ii  adwaita-icon-theme                               43-1                                all          default icon theme of GNOME
  ii  alien                                            8.95.6                              all          convert and install rpm and other packages
  ii  alsa-tools                                       1.2.5-2                             amd64        Console based ALSA utilities for specific hardware
    ```

- rpm. The file used is the output of the following command. **Note** that it is recommended to sort the list of files as this makes it easier to find the packages in the SBOM.
    ```bash
    rpm -qa | sort > [filename.out]
    ```
    
    Sample file contents
    ```console
  accountsservice-0.6.55-10.el9.x86_64
  accountsservice-libs-0.6.55-10.el9.x86_64
  acl-2.3.1-3.el9.x86_64
  adcli-0.9.1-7.el9.x86_64
  adwaita-cursor-theme-40.1.1-3.el9.noarch
  adwaita-icon-theme-40.1.1-3.el9.noarch
    ```  

- windows. The file used is the output of the following command
    ```powershell
    get-wmiobject -class win32_product | Out-file -filePath [filename.out]
    ```
    
    Sample file contents
    ```console 
  IdentifyingNumber : {....}
  Name              : Python 3.10.5 Utility Scripts (64-bit)
  Vendor            : Python Software Foundation
  Version           : 3.10.5150.0
  Caption           : Python 3.10.5 Utility Scripts (64-bit)

    ```
- freebsd
  Sample of pkg info -a 
  ```console
  py39-s3transfer-0.10.1         Amazon S3 Transfer Manager for Python
  py39-setuptools-63.1.0_1       Python packages installer
  py39-six-1.16.0                Python 2 and 3 compatibility utilities
  py39-urllib3-1.26.18,1         HTTP library with thread-safe connection pooling, file post, and more
  py39-yaml-6.0.1                Python YAML parser
  python311-3.11.9               Interpreted object-oriented programming language
  python38-3.8.19_2              Interpreted object-oriented programming language
  python39-3.9.19                Interpreted object-oriented programming language
  readline-8.2.10                Library for editing command lines as they are typed
  sudo-1.9.15p5_4                Allow others to run commands as root
  tiff-4.6.0                     Tools and library routines for working with TIFF images
  xorg-fonts-truetype-7.7_1      X.Org TrueType fonts
  xorgproto-2024.1               X Window System unified protocol definitions
  zstd-1.5.6                     Fast real-time compression algorithm
  ```


If the specified filename is not found, the tool will terminate.

The `--package` option is used to identify the name of a package or application installed on the system. If the specified package or application is not found, the tool terminates.
This option is not supported if the `--distro` option is set to 'windows'.

The `--system` option is used to generate an SBOM for all the applications installed on the system. Note that this option will take some time to complete as it is dependent on the number of installed applications.
This option is not supported if the `--distro` option is set to 'windows'.

The `--root` option is used to specify an alternative directory location for the installed packages. This option only applies for 'deb' distributions.

The `--distro-namespace` option is used to specify a namespace to be included in the generated [PURL](https://github.com/package-url/purl-spec) identifiers for the packages. This is mandatory if the `--input-file` option is specified.

At least one of the `--input-file`, `--package` or `--system` options must be specified. If multiple options are specified, the `--input-file` option followed by the `--system` option will be assumed.

The `--product-type`, `--product-name`, `--product-version` and `--product-author` options allow the specification of the top level
component within the SBOM. These option only apply to CycloneDX SBOMs. The default for product type is 'application' but it is always 'operating-system' if the `--system` option is specified.

The `--sbom` option is used to specify the format of the generated SBOM (the default is SPDX). The `--format` option
can be used to specify the formatting of the SBOM (the default is Tag Value format for a SPDX SBOM). JSON format is supported for both
SPDX and CycloneDX SBOMs.

The `--output-file` option is used to control the destination of the output generated by the tool. The
default is to report to the console but can be stored in a file (specified using `--output-file` option).

## Examples

### SBOM for an Installed Package

To generate an SBOM for the installed zip package.

```bash
distro2sbom --distro auto --name <distro name> --release <distro release> --package zip
```

This will automatically detect the type of distribution and generate an SBOM in SPDX Tag value format to the console.

### SBOM for Distribution

To generate an SBOM for a system distribution.

```bash
distro2sbom --distro deb --name <distro name> --release <distro release> --distro-namespace <namespace> --input-file <distrofile> --sbom cyclonedx --output-file <distrooutfile>
```

This will generate an SBOM in CycloneDX JSON value for a distribution file in dpkg format (indicated by the 'deb' option)

### SBOM for System

To generate an SBOM for an installed system, obtaining the name and release of the system from installed system files.

```bash
distro2sbom --distro deb --system --format json --output-file <distrooutfile>
```

This will generate an SBOM in SPDX JSON value for a distribution file in dpkg format (indicated by the 'deb' option)

#### Specific options for rpm/yum based distro

The following [optional] environment variable are available to customize rpm and yum commands used by the tool. This can be usefull for example to enable/disable some repo or to support *chrooted* environments.

- **DISTRO2SBOM_ROOT_PATH** The path prefix where to get `/etc/os-release`
- **DISTRO2SBOM_RPM_OPTIONS** Additional options passed to rpm commands (used by `rpm -qa` to list all packages and `rpm -qi <pkg>` to query information on a package)
- **DISTRO2SBOM_YUM_OPTIONS** Additional options passed to yum commands (used by `yum repoquery --deplist <pkg>` to get dependencies)

```bash
export DISTRO2SBOM_ROOT_PATH=/path-to-distrib/slash
export DISTRO2SBOM_RPM_OPTIONS="--root /path-to-distrib/slash"
export DISTRO2SBOM_YUM_OPTIONS="--installroot=/path-to-distrib/slash --setopt=reposdir=/path-to-distrib/repos --setopt=install_weak_deps=False --repo=my-repo"
distro2sbom --distro rpm --system --sbom cyclonedx --format json --output-file <distrooutfile>
```

This will generate an SBOM in CYCLONEDX JSON value for a *chrooted* distribution located at `/path-to-distrib/slash`

## Licence

Licenced under the Apache 2.0 Licence.

## Limitations

This tool is meant to support software development and security audit functions. However, the usefulness of the tool is dependent on the SBOM data
which is provided to the tool. Unfortunately, the tool is unable to determine the validity or completeness of such a SBOM file; users of the tool
are therefore reminded that they should assert the quality of any data which is provided to the tool.

When processing and validating licenses, the application will use a set of synonyms to attempt to map some license identifiers to the correct [SPDX License Identifiers](https://spdx.org/licenses/). However, the
user of the tool is reminded that they should assert the quality of any data which is provided by the tool particularly where the license identifier has been modified.

Dependencies between applications are only produced for the `--package` and `--system` options. For Debian distributions, recommends dependencies will be shown with the `--system` option.

The `--package` option is not supported if the `--distro` option is set to 'windows'.

Whilst [PURL](https://github.com/package-url/purl-spec) and [CPE](https://nvd.nist.gov/products/cpe) references are automatically generated for components, the accuracy
of such references cannot be guaranteed as they are dependent on the validity of the data associated with the component.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.