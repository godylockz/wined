#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""This WinDBG script searches for pop-pop-ret gadgets (i.e. pop r32; pop r32; ret) instructions by module name.

Usage:
    0:010> !py \\tsclient\share\wined\findppr.py -b 00 0A 0D
    0:010> !py \\tsclient\share\wined\findppr.py -b 00 02 0a 0d f8 fd -m libspp

References:
- https://github.com/epi052/osed-scripts
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


class PopR32:
    eax = 0x58
    ecx = 0x59
    edx = 0x5A
    ebx = 0x5B
    esp = 0x5C
    ebp = 0x5D
    esi = 0x5E
    edi = 0x5F

    @classmethod
    def get_register_name(cls, value):
        for name, member_value in cls.__dict__.items():
            if isinstance(member_value, int) and member_value == value:
                return name
        raise ValueError("Invalid register value - {}".format(value))


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


def hex_address_to_bytes(addr):
    """
    Convert a hex address to an escaped string and a list of integers.

    Parameters:
        addr (str): Hexadecimal address string.

    Returns:
        tuple: A tuple containing an escaped string and a list of integers.
    """
    import struct

    addr_escaped = ""
    addr_int = []

    # Pack the hex address into a little-endian byte string
    packed_bytes = struct.pack("<I", int(addr, 16))

    # Process each byte in the packed bytes
    for byte in packed_bytes:
        # Convert the byte to an integer
        byte_int = ord(byte) if isinstance(byte, str) else byte
        addr_int.append(byte_int)

        # Build the escaped string representation
        addr_escaped += "\\x{:02X}".format(byte_int)

    return addr_escaped, addr_int


def get_safe_seh_modules():
    """
    Retrieves a list of module names with SafeSEH set to OFF using the Narly WinDbg extension.

    Returns:
    list: A list of module names with SafeSEH set to OFF.
    """
    # List to store modules with SafeSEH OFF
    modules = []

    # Run Narly to get information about SafeSEH status
    result = pykd.dbgCommand(".load narly; !nmod /SafeSEH")

    # Iterate through each line in the result
    for line in result.splitlines():
        # Check if the line indicates SafeSEH is OFF
        if "/SafeSEH OFF" in line:
            # Add the module name to the list
            modules.append(line.split()[2])

    # Return the list of modules with SafeSEH OFF
    return modules


class Module:
    def __init__(self, unparsed):
        self.name = "unknown"
        self.start = -1
        self.end = -1
        self.unparsed = unparsed.split()
        self.parse()

    def parse(self):
        if len(self.unparsed) >= 3:
            self.start = self.unparsed[0]
            self.end = self.unparsed[1]
            self.name = self.unparsed[2]

    def __str__(self):
        return "{}(start={}, end={})".format(self.name, self.start, self.end)


def get_all_modules():
    """
    Retrieves a list of all modules using the 'lm' command.

    Returns:
    List[Module]: A list of Module objects representing the modules.
    """
    modules = []
    for mod_line in pykd.dbgCommand("lm").splitlines():
        modules.append(Module(mod_line))
    return modules


def contains_bad_chars(address, badchars):
    """
    Checks if any byte in the given address matches any of the specified bad characters.

    Args:
    address (str): The address to check for bad characters.
    badchars (list): List of bad characters to compare against.

    Returns:
    bool: True if any byte in the address matches a bad character, False otherwise.
    """
    for addr_byte in address:
        for bad_byte in badchars:
            # Check if the byte in the address matches any bad character
            if bad_byte == addr_byte:
                return True
    # No matching bad characters found in the address
    return False


def get_pageprotection(address):
    """Get page protection"""
    command = "!vprot {}".format(address)
    # print("[*] Running {}".format(command))
    output = pykd.dbgCommand(command)
    search_val = "Protect:           "
    if search_val in output:
        return int(output.split(search_val)[1].split(" ")[0], 16)
    return 0


def search_gadgets_in_module(module, pop_range, badchars):
    """Search for gadgets in the specified module within the given pop range."""
    num_gadgets = 0

    for pop1 in pop_range:
        for pop2 in pop_range:
            command = "s-[1]b {} {} {} {} c3".format(module.start, module.end, hex(pop1), hex(pop2))
            result = pykd.dbgCommand(command)

            if result is None:
                continue

            for addr in result.splitlines():
                addr_escaped, addr_int = hex_address_to_bytes(addr)
                is_bad = contains_bad_chars(addr_int, badchars)

                page_protection = get_pageprotection(addr)
                if page_protection in [PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY]:
                    page_protection = "R/X"
                if page_protection in [PAGE_READWRITE]:
                    page_protection = "R/W"

                if not is_bad:
                    print("[+] {}::{}: {} pop {}; pop {}; ret ; {}".format(module.name, addr, page_protection, PopR32.get_register_name(pop1), PopR32.get_register_name(pop2), addr_escaped))
                    num_gadgets += 1

    return num_gadgets


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Searches for pop-pop-ret gadgets (i.e. pop r32; pop r32; ret) instructions by module name.")
    parser.add_argument(
        "-b",
        "--bad",
        help="Hex bytes that are already known bad (ex: -b 00 0a 0d or -b 000a0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )
    parser.add_argument("-m", "--modules", help="Module name(s) to search for pop pop ret (ex: findppr.py libspp diskpls libpal)", nargs="+", default=[])
    args = parser.parse_args()

    # Parse bad characters
    if args.bad:
        args.bad = [b for bad in args.bad for b in bad]
        bad_hexstr = " ".join("\\x{:02X}".format(i) for i in args.bad)
        if bad_hexstr:
            print("[*] Bad Characters: {}".format(bad_hexstr))

    # If modules are not specified, get SafeSEH modules
    if not args.modules:
        args.modules = get_safe_seh_modules()
    if not args.modules:
        print("[-] Unable to find SafeSEH modules")
        sys.exit(1)

    # Initialize
    total_gadgets = 0  # This tracks all the total number of usable gadgets
    mod_gadget_count = {}  # This tracks the number of gadgets per module

    # Parse modules
    all_modules = get_all_modules()

    for module_name in args.modules:
        # Initializations
        num_gadgets = 0  # This is the number of gadgets found in this module

        # Find the module with a case-insensitive match to the user's input
        matching_modules = [mod for mod in all_modules if mod.name.lower() == module_name.lower()]
        if not matching_modules:
            print("[-] Unable to find module {}".format(module_name.lower()))
            continue

        module = matching_modules[0]

        # Parse gadgets in the selected module
        print("[*] Searching {} for Pop/Pop/Ret instruction".format(module.name))
        num_gadgets = search_gadgets_in_module(module, range(0x58, 0x60), args.bad)

        print("[+] {}: Found {} usable gadgets!".format(module.name, num_gadgets))
        mod_gadget_count[module.name] = num_gadgets
        total_gadgets += num_gadgets

    # Print stats
    print("\n---- STATS ----")  # Print out all the stats
    if bad_hexstr:
        print(">> BADCHARS: {}".format(bad_hexstr))
    print(">> Usable Gadgets Found: {}".format(total_gadgets))
    print(">> Module Gadget Counts")
    for m, c in mod_gadget_count.items():
        print("   - {}: {} ".format(m, c))


if __name__ == "__main__":
    main()
    print("[*] Done!")
