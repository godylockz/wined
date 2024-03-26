#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""This WinDBG script searches for codecave (continuous null bytes) in executable memory regions.

Usage:
    0:010> !py \\tsclient\share\wined\findcave.py -s <START_ADDRESS> -e <END_ADDRESS>
    0:010> !py \\tsclient\share\wined\findcave.py -m libspp

References:
- https://github.com/nop-tech/code_caver/blob/main/code_caver.py
"""

# Imports
import argparse
import sys

try:
    import pykd
except ImportError:
    print("pykd module not available. Make sure you are running this script inside WinDBG.")
    sys.exit(1)

# Globals
# https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80


class Module:
    def __init__(self, lm_str):
        self.name = "unknown"
        self.start = -1
        self.end = -1
        try:
            if lm_str:
                unparsed_split = lm_str.split()
                if len(unparsed_split) >= 3:
                    self.start = int(unparsed_split[0], 16)
                    self.end = int(unparsed_split[1], 16)
                    self.name = unparsed_split[2]
        except:
            pass

    def __str__(self):
        return "{} (start=0x{:x}, end=0x{:x})".format(self.name, self.start, self.end)


def get_all_modules():
    """
    Retrieves a list of all modules using the 'lm' command.

    Returns:
    List[Module]: A list of Module objects representing the modules.
    """
    modules = []
    for mod_line in pykd.dbgCommand("lm").splitlines():
        if mod_line:
            mod_parsed = Module(mod_line)
            if mod_parsed.start != -1:
                modules.append(mod_parsed)
    return modules


def get_pageprotection(address):
    """Get page protection"""
    command = "!vprot 0x{:x}".format(address)
    # print("[*] Running {}".format(command))
    output = pykd.dbgCommand(command)
    search_val = "Protect:           "
    if search_val in output:
        return int(output.split(search_val)[1].split(" ")[0], 16)
    return 0


def find_codecaves(search_start_address, search_end_address, min_size, module=None):
    """Find code-caves (continuous null bytes) to store shellcode/arguments"""

    if module:
        print("[*] Scanning for code-caves in module {} (range 0x{:08x} to 0x{:08x})".format(module.name, search_start_address, search_end_address))
    else:
        print("[*] Scanning for code caves in the address range 0x{:08x} to 0x{:08x}".format(search_start_address, search_end_address))

    # Search for nulls
    command = "s -[1]b 0x{:x}  L0n{} 00".format(search_start_address, search_end_address - search_start_address)
    # print("[*] Running {}".format(command))
    output = pykd.dbgCommand(command)

    # Extract the addresses where null bytes are found
    null_addresses = [int(addr, 16) for addr in output.strip().split("\n")]
    print("[*] Found {} null bytes".format(len(null_addresses)))

    # Find executable null addresses
    executable_nulls = []
    readwrite_nulls = []
    for addr in null_addresses:
        page_protection = get_pageprotection(addr)
        if page_protection in [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY]:
            executable_nulls.append(addr)
        if page_protection in [PAGE_READWRITE]:
            readwrite_nulls.append(addr)
    print("[*] Found {} read/write null bytes".format(len(readwrite_nulls)))
    print("[*] Found {} executable null bytes".format(len(executable_nulls)))

    # Identify consecutive executable null bytes
    codecaves = []
    n = len(executable_nulls)
    i = 0
    while i < n:
        addr = executable_nulls[i]
        codecave_size = 1

        # Keep incrementing size until the sequence breaks or end of array is reached
        while i + codecave_size < n and executable_nulls[i + codecave_size] == addr + codecave_size:
            codecave_size += 1

        if codecave_size >= min_size:
            end_address = addr + codecave_size
            if module:
                # Ensure the difference is within the valid range for a 32-bit unsigned integer
                diff = (addr - module.start) % (2**32)
                # Ensure we keep it a multiple of 4
                modadd = 4 - (diff % 4)
                diff += modadd
                addr += modadd
                codecave_size -= modadd
                print("[+] Executable code-cave at {}+0x{:08x} 0x{:08x} - 0x{:08x} ({} bytes)".format(module.name, diff, addr, end_address, codecave_size))
            else:
                print("[+] Executable code-cave at 0x{:08x} - 0x{:08x} ({} bytes)".format(addr, end_address, codecave_size))
            codecaves.append({"start_address": addr, "end_address": end_address, "size": codecave_size, "permission": "executable"})

        # Move to the next index after the current group
        i += max(codecave_size, 1)

    # Identify consecutive writable null bytes
    n = len(readwrite_nulls)
    i = 0
    while i < n:
        addr = readwrite_nulls[i]
        codecave_size = 1

        # Keep incrementing size until the sequence breaks or end of array is reached
        while i + codecave_size < n and readwrite_nulls[i + codecave_size] == addr + codecave_size:
            codecave_size += 1

        if codecave_size >= min_size:
            end_address = addr + codecave_size
            if module:
                # Ensure the difference is within the valid range for a 32-bit unsigned integer
                diff = (addr - module.start) % (2**32)
                # Ensure we keep it a multiple of 4
                modadd = 4 - (diff % 4)
                diff += modadd
                addr += modadd
                codecave_size -= modadd
                print("[+] Writable code-cave at {}+0x{:08x} 0x{:08x} - 0x{:08x} ({} bytes)".format(module.name, diff, addr, end_address, codecave_size))
            else:
                print("[+] Writable code-cave at 0x{:08x} - 0x{:08x} ({} bytes)".format(addr, end_address, codecave_size))
            codecaves.append({"start_address": addr, "end_address": end_address, "size": codecave_size, "permission": "writable"})

        # Move to the next index after the current group
        i += max(codecave_size, 1)

    return codecaves


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Search for code caves in selected module")
    parser.add_argument("-m", "--modules", help="Module name(s) to search within", nargs="+", default=[])
    parser.add_argument("-s", "--start", type=str, help="Enter the start hex address", default="")
    parser.add_argument("-e", "--end", type=str, help="Enter the end hex address", default="")
    parser.add_argument("-t", "--target", type=int, help="Minimum number of null bytes to find", default=408)
    args = parser.parse_args()

    if args.modules:
        # Search within specific modules
        all_modules = get_all_modules()
        for module_name in args.modules:
            matching_modules = [mod for mod in all_modules if mod.name.lower() == module_name.lower()]
            if not matching_modules:
                print("[-] Unable to find module {}".format(module_name.lower()))
                continue
            module = matching_modules[0]

            try:
                find_codecaves(module.start, module.end, args.target, module=module)
            except KeyboardInterrupt:
                print("[!] Script interrupted by user.")

    elif args.start and args.end:
        try:
            start_address = int(args.start, 16)
            end_address = int(args.end, 16)

        except ValueError as e:
            print(e)
            sys.exit(0)

        try:
            find_codecaves(start_address, end_address, args.target)
        except KeyboardInterrupt:
            print("[!] Script interrupted by user.")

    else:
        parser.print_usage()


if __name__ == "__main__":
    main()
    print("[*] Done!")
