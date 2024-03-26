#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""This WinDBG script finds the IAT address of the ROP DEP bypass (VA, WPM, VP) function. If its not found, then it finds one that is (i.e. WriteFile) and calculates the offset of the function you'd like from the the resolved address of that function IAT entry,

Usage:
    0:010> !py \\tsclient\share\wined\findiat.py libspp WriteProcessMemoryStub

References:
- https://github.com/ksecurity45/osed-scripts-1/blob/main/find-function-iat.py
"""

# Imports
import argparse
import sys

try:
    import pykd
except ImportError:
    print("pykd module not available. Make sure you are running this script inside WinDBG.")
    sys.exit(1)


def hex_byte(byte_str):
    """
    Validate user input as a hex representation of an int between 0 and 255 inclusive.

    Args:
    - byte_str (str or list): The input string or list to be validated.

    Returns:
    - int or list: If input is a valid hex byte string, return the integer value;
                  If input is already a list, assume it's a list of integers and return it.

    Raises:
    - argparse.ArgumentTypeError: If the input is not a valid hex byte string or list of integers.
    """
    if isinstance(byte_str, list):
        # If it's already a list, assume it's a list of integers
        try:
            for val in byte_str:
                if not (0 <= val <= 255):
                    raise ValueError
            return byte_str
        except ValueError:
            raise argparse.ArgumentTypeError("Only *hex* bytes between 00 and ff are valid, found {}".format(byte_str))
    else:
        # If it's a string, process it as before
        if byte_str == "??":
            # WinDBG shows ?? when it can't access a memory region, but we shouldn't stop execution because of it
            return byte_str

        # Remove any spaces from the input string
        byte_str = byte_str.replace(" ", "").replace(",", "").replace("\\x", "").replace("\\", "")

        # Split the input string into two characters each and convert to integers
        bytes_list = [int(byte_str[i : i + 2], 16) for i in range(0, len(byte_str), 2)]

        try:
            for val in bytes_list:
                if not (0 <= val <= 255):
                    raise ValueError

            return bytes_list
        except ValueError:
            raise argparse.ArgumentTypeError("Only *hex* bytes between 00 and ff are valid, found {}".format(byte_str))


class AddrResolver:
    def __init__(self, module, func):
        self.module = module
        self.func = func
        try:
            self.image_base = pykd.module(self.module).begin()
        except:
            print("[-] Unable to find module {}".format(self.module))
            exit()
        self.iat_offset = int()
        self.iat_size = int()
        self.entries = dict()

    def find_lines_containing(self, lines, string):
        result = list()
        for line in lines:
            if string in line:
                result.append(line)
        return result

    def get_iat_info(self):
        result = pykd.dbgCommand("!dh {} -f".format(self.module))
        line = self.find_lines_containing(result.splitlines(), "Import Address Table Directory")[0]
        self.iat_offset = int(line[:8], 16)
        self.iat_size = int(line[10:18], 16)

    def proc_iat_entries(self, entries):
        processed = dict()
        for entry in entries:
            processed[entry[2]] = {"iat": int(entry[0], 16), "resolved": int(entry[1], 16)}
        return processed

    def get_kernel32_iat_entries(self):
        # dps <start> <end>
        result = pykd.dbgCommand("dps {} {}".format(hex(self.image_base + self.iat_offset).rstrip("L"), hex(self.image_base + self.iat_offset + self.iat_size)).rstrip("L"))
        lines = self.find_lines_containing(result.splitlines(), "KERNEL32!")
        self.entries = self.proc_iat_entries([line.split() for line in lines])

    def try_get_func(self):
        va = "KERNEL32!{}".format(self.func)
        if va in self.entries:
            print("[+] {} ({} IAT entry)".format(hex(self.entries[va]["iat"]), self.func))
        else:
            print("[-] Couldn't find {}".format(self.func))

    def resolve(self):
        self.get_iat_info()
        self.get_kernel32_iat_entries()
        self.try_get_func()


def main():
    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("module", help="Module name")
    parser.add_argument("func", choices=["VirtualAllocStub", "WriteProcessMemoryStub", "VirtualProtectStub"])
    parser.add_argument("-a", "--all", help="Show all IAT addresses")
    parser.add_argument(
        "-b",
        "--bad",
        help="Hex bytes that are already known bad (ex: -b 00 0a 0d or -b 000a0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )
    args = parser.parse_args()

    # Parse bad characters
    if args.bad:
        args.bad = [b for bad in args.bad for b in bad]
        bad_hexstr = " ".join("\\x{:02X}".format(i) for i in args.bad)
        if bad_hexstr:
            print("[*] Bad Characters: {}".format(bad_hexstr))

    # Attempt to resolve
    resolver = AddrResolver(args.module, args.func)
    resolver.resolve()

    # Resolve va
    va_resolved = int(pykd.dbgCommand("x KERNEL32!{}".format(resolver.func))[:8], 16)

    # Loop alternative entries
    for alt_entry in list(resolver.entries.keys()):
        offset = va_resolved - resolver.entries[alt_entry]["resolved"]
        neg = (0xFFFFFFFFFFFFFFFF - abs(offset) + 1) & 0xFFFFFFFF

        print("[*] Using {}".format(alt_entry))
        print("[+] {} ({} IAT entry)".format(hex(resolver.entries[alt_entry]["iat"]), alt_entry[9:]))
        print("[+] {} ({} resolved)".format(hex(resolver.entries[alt_entry]["resolved"]), alt_entry[9:]))
        print("[+] {} ({} resolved)".format(hex(va_resolved), args.func))
        print("[+] {} (offset = {} - {})".format(hex(offset), args.func, alt_entry[9:]))
        print("[+] {} (negative)".format(hex(neg).rstrip("L")))
        if not args.all:
            break


if __name__ == "__main__":
    main()
    print("[*] Done!")
