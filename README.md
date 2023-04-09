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
usage: distro2sbom [-h] [--distro {rpm,deb,windows,auto}] [-i INPUT_FILE] [-n NAME] [-r RELEASE] [-p PACKAGE] [-s] [-d] [--sbom {spdx,cyclonedx}] [--format {tag,json,yaml}]
                   [-o OUTPUT_FILE] [-V]

Distro2Sbom generates a Software Bill of Materials for the specified package or distribution.

options:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

Input:
  --distro {rpm,deb,windows,auto}
                        type of distribution
  -i INPUT_FILE, --input-file INPUT_FILE
                        name of distribution file
  -n NAME, --name NAME  name of distribution
  -r RELEASE, --release RELEASE
                        release identity of distribution
  -p PACKAGE, --package PACKAGE
                        identity of package within distribution
  -s, --system          generate SBOM for installed system

Output:

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

The `--distro` option is used to identify the type of distribution. The auto option attempts to determine the type of distribution by searching for the
presence of key applications required by the tool. If none of the required applications are found, the tool terminates. This option is mandatory.

The `--name` option and `--release` option is used to identify the name and release of the distribution. These options are both mandatory.

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

If the specified filename is not found, the tool will terminate.

The `--package` option is used to identify the name of a package or application installed on the system. If the specified package or application is not found, the tool terminates.
This option is not supported if the `--distro` option is set to 'windows'.

The `--system` option is used to generate an SBOM for all the applications installed on the system. Note that this option will take some time to complete as it is dependent on the number of installed applications.
This option is not supported if the `--distro` option is set to 'windows'.

At least one of the `--input-file`, `--package` or `--system` options must be specified. If multiple options are specified, the `--input-file` option followed by the `--system` option will be assumed.

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
distro2sbom --distro deb --name <distro name> --release <distro release> --input-file <distrofile> --sbom cyclonedx --output-file <distrooutfile>
```

This will generate an SBOM in CycloneDX JSON value for a distribution file in dpkg format (indicated by the 'deb' option)

### SBOM for System

To generate an SBOM for an installed system.

```bash
distro2sbom --distro rpm --name <distro name> --release <distro release> --system --format json --output-file <distrooutfile>
```

This will generate an SBOM in SPDX JSON value for a distribution file in dpkg format (indicated by the 'deb' option)

## Licence

Licenced under the Apache 2.0 Licence.

## Limitations

This tool is meant to support software development and security audit functions. However, the usefulness of the tool is dependent on the SBOM data
which is provided to the tool. Unfortunately, the tool is unable to determine the validity or completeness of such a SBOM file; users of the tool
are therefore reminded that they should assert the quality of any data which is provided to the tool.

When processing and validating licenses, the application will use a set of synonyms to attempt to map some license identifiers to the correct [SPDX License Identifiers](https://spdx.org/licenses/). However, the
user of the tool is reminded that they should assert the quality of any data which is provided by the tool particularly where the license identifier has been modified.

Dependencies between applications are only produced for the `--package` and `--system` options.

The `--package` option is not supported if the `--distro` option is set to 'windows'.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.