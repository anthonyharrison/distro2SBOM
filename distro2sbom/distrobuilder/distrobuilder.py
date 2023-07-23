# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import re
import subprocess
import unicodedata
from pathlib import Path


class DistroBuilder:
    def __init__(self, debug=False):
        self.sbom_packages = {}
        self.sbom_relationships = []
        self.debug = debug

    def get_data(self):
        pass

    def parse_data(self):
        pass

    def process_system(self):
        print("[ERROR] Feature not available")

    def run_program(self, command_line):
        # Remove any null bytes
        command_line = command_line.replace("\x00", "")
        # Split command line into individual elements
        params = command_line.split()
        res = subprocess.run(params, capture_output=True, text=True)
        return res.stdout.splitlines()

    def format_supplier(self, supplier_info, include_email=True):
        # See https://stackoverflow.com/questions/1207457/convert-a-unicode-string-to-a-string-in-python-containing-extra-symbols
        # And convert byte object to a string
        name_str = (
            unicodedata.normalize("NFKD", supplier_info)
            .encode("ascii", "ignore")
            .decode("utf-8")
        )
        if " " in name_str:
            # Get names assumed to be at least two names <first> <surname>
            names = re.findall(r"[a-zA-Z\.\]+ [A-Za-z]+ ", name_str)
        else:
            # Handle case where only single name provided
            names = [name_str]
        # Get email addresses
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,
        )
        supplier = " ".join(n for n in names)
        if include_email and len(emails) > 0:
            # Only one email can be specified, so choose last one
            supplier = supplier + "(" + emails[-1] + ")"
        return re.sub(" +", " ", supplier.strip())

    def get_packages(self):
        return self.sbom_packages

    def get_relationships(self):
        if self.debug:
            print(self.sbom_relationships)
        return self.sbom_relationships

    def get_parent(self):
        return self.parent

    def get_system(self):
        # Extract metadata from file
        OS_FILE = "/etc/os-release"
        metadata = {}
        filePath = Path(OS_FILE)
        # Check path exists and is a valid file
        if filePath.exists() and filePath.is_file():
            os_file = open(OS_FILE)
            lines = os_file.readlines()
            for line in lines:
                data = line.split("=")
                metadata[data[0].lower()] = data[1].replace('"', "").strip()
        return metadata
