#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""This WinDBG script provides search functionality.

Usage:
    0:010> !py \\tsclient\share\wined\search.py -t ascii fafd
    0:010> !py \\tsclient\share\wined\search.py -t ascii ffff

References:
- https://github.com/epi052/osed-scripts/blob/main/search.py
- https://github.com/epi052/osed-scripts/blob/main/findbad-chars.py
"""

# Imports
import argparse
import re

try:
    import pykd
except ImportError:
    print("Do not run outside WinDBG")
    exit(1)


class Opcodes:
    # http://ref.x86asm.net/coder32.html
    ret = 0xC3
    pop_eax = 0x58
    pop_ecx = 0x59
    pop_edx = 0x5A
    pop_ebx = 0x5B
    pop_esp = 0x5C
    pop_ebp = 0x5D
    pop_esi = 0x5E
    pop_edi = 0x5F
    jmp = 0xFF
    jmp_eax = 0xE0
    jmp_ecx = 0xE1
    jmp_edx = 0xE2
    jmp_ebx = 0xE3
    jmp_esp = 0xE4
    jmp_ebp = 0xE5
    jmp_esi = 0xE6
    jmp_edi = 0xE7
    shortjmp = 0xEB  # Second opcode is the relative offset, which ranges from 0x00 to 0x7F for forward short jumps, and from 0x80 to 0xFF for backwards short jumps
    xor = 0x31
    test = 0x85
    condition_eax = 0xC0  # 31C0 xor eax,eax
    condition_ecx = 0xC9  # 31C9 xor ecx,ecx
    condition_edx = 0xD2  # 31D2 xor edx,edx
    condition_ebx = 0xD8  # 31D8 xor ebx,ebx
    condition_esp = 0xE4  # 31E4 xor esp,esp
    condition_ebp = 0xED  # 31ED xor ebp,ebp
    condition_esi = 0xF6  # 31F6 xor esi,esi
    condition_edi = 0xFF  # 31FF xor edi,edi

    @classmethod
    def get_opcode(cls, value):
        for name, member_value in cls.__dict__.items():
            if isinstance(member_value, int) and member_value == value:
                return name.replace("_", " ")
        raise ValueError("Invalid register value - {}".format(value))


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


def parse_registers():
    from collections import OrderedDict

    # Get registers
    result = pykd.dbgCommand("r")
    result = result.replace("\n", " ")

    registers = OrderedDict()

    # Split the input string by spaces
    parts = result.split()

    # Iterate through the parts and identify register information
    for part in parts:
        if "=" in part and not "=+" in part:
            key, value = part.split("=")
            # Store register values in the dictionary
            registers[key] = int(value, 16)

    return registers


def address_to_bytes(address):
    """
    Convert an address to an escaped string and a list of integers.

    Parameters:
        address (int): Integer address.

    Returns:
        tuple: A tuple containing an escaped string and a list of integers.
    """
    import struct

    addr_escaped = ""
    addr_int = []

    # Pack the hex address into a little-endian byte string
    packed_bytes = struct.pack("<I", address)

    # Process each byte in the packed bytes
    for byte in packed_bytes:
        # Convert the byte to an integer
        byte_int = ord(byte) if isinstance(byte, str) else byte
        addr_int.append(byte_int)

        # Build the escaped string representation
        addr_escaped += "\\x{:02X}".format(byte_int)

    return addr_escaped, addr_int


def get_stack_range():
    teb_info = pykd.dbgCommand("!teb")
    match = re.search(r"StackBase:\s+([0-9a-fA-F]+)\s+StackLimit:\s+([0-9a-fA-F]+)", teb_info)
    if match:
        stack_base = match.group(1)
        stack_limit = match.group(2)
        return stack_base, stack_limit
    else:
        print("[!] Error extracting StackBase and StackLimit from TEB")
        exit(1)


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


def search_memory(args):
    search_type = {"byte": "-b", "bytes": "-b", "ascii": "-a", "unicode": "-u"}.get(args.type)

    # Parse search pattern
    pattern = args.pattern
    pattern_parsed = ""
    if search_type == "-b":
        # Ensure spacing between every two characters
        pattern = " ".join(pattern[i : i + 2] for i in range(0, len(pattern), 2) if len(pattern[i : i + 2]) == 2)

        # Parse pattern bytes -> opcode
        for b in pattern.split():
            try:
                op = Opcodes.get_opcode(int(b, 16))
                pattern_parsed += "{};".format(op)
            except:
                pass
        if pattern_parsed:
            print("[*] Searching for {}".format(pattern_parsed))
        else:
            print("[*] Searching for {}".format(pattern))
    else:
        print("[*] Searching for {}".format(pattern))

    # Parse registers:
    registers = parse_registers()

    if args.teb:
        # Search teb
        stack_base, stack_limit = get_stack_range()
        command = "s {} {} {} {}".format(search_type, stack_limit, stack_base, pattern)
        run_search(command, args, registers)
    elif args.modules:
        # Search within specific modules
        all_modules = get_all_modules()
        for module_name in args.modules:
            matching_modules = [mod for mod in all_modules if mod.name.lower() == module_name.lower()]
            if not matching_modules:
                print("[-] Unable to find module {}".format(module_name.lower()))
                continue
            module = matching_modules[0]
            command = "s {} {} {} {}".format(search_type, module.start, module.end, pattern)
            run_search(command, args, registers, module=module)
    else:
        # Global search
        command = "s {} 0 L?80000000 {}".format(search_type, pattern)
        run_search(command, args, registers)


def run_search(command, args, registers, module=None):
    print("0:000> {}".format(command))
    result = pykd.dbgCommand(command)
    all_results = []
    if result is None:
        print("[!] No results returned")
    else:
        for line in result.splitlines():
            addr_hexstr = line.split("  ")[0].lstrip("0")
            addr_int = int(addr_hexstr, 16)
            addr_escaped, addr_bytes = address_to_bytes(addr_int)
            if module:
                print_statement = "{}:0x{} {}".format(module.name, addr_hexstr, addr_escaped)
            else:
                print_statement = "0x{} {}".format(addr_hexstr, addr_escaped)
            try:
                # Calculate stack offset to each result
                offset = addr_int - registers["esp"]
                diff = diff % (2**32)  # Ensure the difference is within the valid range for a 32-bit unsigned integer
                diff += 4 - (diff % 4)  # Ensure that when modifying ESP, keep it a multiple of 4
                print_statement += " | Stack Offset: {}".format(offset)
            except:
                pass
            if print_statement in all_results:
                continue
            all_results.append(print_statement)
            is_bad = contains_bad_chars(addr_bytes, args.bad)
            if not is_bad:
                print("[+] {}".format(print_statement))
            else:
                print("[-] {}".format(print_statement))

            # Dump bytes
            if args.dump and addr_hexstr:
                command = "db 0x{} L0n{}".format(addr_hexstr, args.num_bytes)
                print("0:000> {}".format(command))
                result = pykd.dbgCommand(command)
                if result is None:
                    print("[!] No results returned")
                print(result)
                addr_hexstr

            # First result
            if args.first:
                return


def main():
    parser = argparse.ArgumentParser(description="Searches memory for the given search term")

    parser.add_argument(
        "-t",
        "--type",
        default="byte",
        choices=["byte", "bytes", "ascii", "unicode"],
        help="Data type to search for (default: byte)",
    )
    parser.add_argument(
        "--teb",
        action="store_true",
        help="Search within the current memory region specified by the TEB",
    )
    parser.add_argument(
        "-b",
        "--bad",
        help="Hex bytes that are already known bad (ex: -b 00 0a 0d or -b 000a0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )
    parser.add_argument(
        "--seh",
        action="store_true",
        help="Enable SEH-Safe Modules",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        help="Dump bytes at every find",
    )
    parser.add_argument(
        "--first",
        action="store_true",
        help="Find first result only",
    )
    parser.add_argument("-n", "--num-bytes", type=int, help="Number of bytes to dump", default=255)
    parser.add_argument("-e", "--egg", help="Find egg and dump memory at first instance", default="")
    parser.add_argument("-m", "--modules", help="Module name(s) to search within", nargs="+", default=[])
    parser.add_argument(
        "-p",
        "--pattern",
        nargs="+",
        help="What you want to search for",
    )

    args = parser.parse_args()

    # Check if egg:
    if args.egg:
        if len(args.egg) == 4:
            args.pattern = args.egg * 2
        else:
            parser.error("Egg should be 4 characters")
        args.type = "ascii"
        args.dump = True

    # Check if at least one pattern is provided
    if not args.pattern:
        parser.error("At least one pattern is required.")

    # If modules are not specified, get SafeSEH modules
    if not args.modules and args.seh:
        args.modules = get_safe_seh_modules()

    # Parse bad characters
    if args.bad:
        args.bad = [b for bad in args.bad for b in bad]
        bad_hexstr = " ".join("\\x{:02X}".format(i) for i in args.bad)
        if bad_hexstr:
            print("[*] Bad Characters: {}".format(bad_hexstr))

    # Searh memory
    args.pattern = "".join(args.pattern)
    if args.pattern == "ppr" or args.pattern == "pop pop ret":
        # pop-pop-ret searching
        print("[*] Pattern: pop-pop-ret".format(args.pattern))
        for i in range(0x58, 0x60):
            for j in range(0x58, 0x60):
                args.pattern = "{}{}{}".format(hex(i)[2:], hex(j)[2:], hex(Opcodes.ret)[2:])
                search_memory(args)
    elif args.pattern == "pr" or args.pattern == "pop ret":
        # pop-ret searching
        print("[*] Pattern: pop-ret".format(args.pattern))
        for i in range(0x58, 0x60):
            args.pattern = "{}{}{}".format(hex(i)[2:], hex(Opcodes.ret)[2:])
            search_memory(args)
    else:
        print("[*] Pattern: {}".format(args.pattern))
        search_memory(args)


if __name__ == "__main__":
    main()
    print("[*] Done!")
