#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This script is used to find/categorize gadgets within an input binary or post-process rp/mona output.

Usage:
    PS> py \\tsclient\share\wined\gadgetizer.py -f C:\shared\rainbow2.exe

References:
- https://github.com/epi052/osed-scripts/blob/main/findgadgets.py
- https://gist.github.com/JohnHammond/23d04ed8614192453e80f97d301e38d3
- https://github.com/ksecurity45/osed-scripts-1/blob/main/rp%2B%2B_filter.py
"""

# Imports
import argparse
import logging
import os
import platform
import re
import string
from struct import pack
import subprocess

##########################
# Utilities
##########################


def log(message):
    ANSI_ESCAPE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    logging.info(ANSI_ESCAPE.sub("", message))
    print(message)


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


def read_file(filename):
    try:
        with open(filename, "r") as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
            return lines
    except IOError:
        log("Error: Unable to read file:", filename)
        return None


def is_binary_file(filename):
    try:
        with open(filename, "rb") as f:
            for block in f:
                if b"\0" in block:
                    return True  # File contains null bytes, hence binary
                elif any(char for char in block if chr(char) not in string.printable):
                    return True  # File contains non-printable characters, hence binary
        return False  # File is text
    except IOError:
        log("Error: Unable to read file:", filename)
        return False


def contains_bad_chars(address, args):
    """
    Checks if any byte in the given address matches any of the specified bad characters.

    Args:
    address (str): The address to check for bad characters.
    badchars (list): List of bad characters to compare against.

    Returns:
    bool: True if any byte in the address matches a bad character, False otherwise.
    """
    if not args.bad:
        return False
    if isinstance(address, str):
        address_bytes = pack("<I", int(address, 16))
    elif isinstance(address, int):
        address_bytes = pack("<I", address)
    elif isinstance(address, bytes):
        address_bytes = address
    else:
        log("[-] Error unknown address type")
        exit()
    if args.aslr:
        # Only compare first two bytes in ASLR mode
        address_bytes = address_bytes[:2]
    for addr_byte in address_bytes:
        for bad_byte in args.bad:
            # Check if the byte in the address matches any bad character
            if bad_byte == addr_byte:
                return True
    # No matching bad characters found in the address
    return False


def run_rp(input_file, args):
    """This function runs rp++ on the specified input file."""

    # Check if rp++ exists
    rp = None
    if platform.system() == "Linux":
        for path_dir in os.environ["PATH"].split(os.pathsep):
            binary_path = os.path.join(path_dir, "rp")
            if os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
                rp = binary_path
                break
            binary_path = os.path.join(path_dir, "rp-lin-x64")
            if not rp and os.path.isfile(binary_path) and os.access(binary_path, os.X_OK):
                rp = binary_path
                break
    else:
        desktop_path = os.path.join(os.getenv("USERPROFILE"), "Desktop")
        executable_path = os.path.join(desktop_path, "rp.exe")
        if os.path.isfile(executable_path):
            rp = executable_path
        desktop_path = os.path.join(os.getenv("USERPROFILE"), "Desktop")
        executable_path = os.path.join(desktop_path, "rp-win-x86.exe")
        if not rp and os.path.isfile(executable_path):
            rp = executable_path
        executable_path = os.path.join("C:", "tools", "dep", "rp-win-x86.exe")
        if not rp and os.path.isfile(executable_path):
            rp = executable_path

    if not rp:
        log("[!] Unable to run rp, download/compile from https://github.com/0vercl0k/rp")
        exit()

    # Run rp++
    log("[*] Running rp++ on {}".format(input_file))
    rp_command = "{} -f {} -r{}".format(rp, input_file, args.length)
    if args.bad:
        # Unique gadgets when bad characters set
        rp_command += " --unique"
        bad_bytes = "".join(["\\x{}".format(byte) for byte in args.bad])
        rp_command += " --bad-bytes={}".format(bad_bytes)
    if args.aslr:
        # Use relative virtual addressing
        rp_command += " --va=0"

    output = subprocess.check_output(rp_command, shell=True)
    rp_output = output.decode().splitlines()
    return rp_output


def filter_gadgets(lines, args):
    """Normalize and filter gadgets."""
    normal_spaces = re.compile(r"[ ]{2,}")
    normal_delimiter = re.compile(r"[ ]+?;")
    large_return = re.compile(r"retn 0x[0-9a-fA-F]{3,}")
    rp_ending = re.compile(r"; \(\d+ found\)")
    all_zeros = re.compile("0x0+(?![0-9a-fA-F]+)")
    null_ret = re.compile("retn 0$")
    normal_comams = re.compile(",\s*")
    normal_retn = re.compile("retn\s*$")
    leading_zeros = re.compile("0x0+")
    all_registers = ["eax", "ax", "ah", "al", "ebx", "bx", "bh", "bl", "ecx", "cx", "ch", "cl", "edx", "dx", "dh", "dl", "edi", "di", "esi", "si", "ebp", "bp", "esp", "sp"]
    find_reg = re.compile(r"\b(" + "|".join(all_registers) + r")\b")
    address_delimiter = ":"
    rp_instruction_delimiter = ";"
    mona_instruction_deimiter = "#"

    gadgets = []
    log("[*] Parsing {} lines ...".format(len(lines)))
    for line in lines:
        # Strip whitespace
        line = line.strip().lower()

        # Check if line starts with address
        if not line.startswith("0x"):
            continue

        # Check if line contains address delimiter
        if not (address_delimiter in line):
            continue

        # Instruction delimiter
        if not (rp_instruction_delimiter in line):
            if mona_instruction_deimiter in line:
                line = line.replace(mona_instruction_deimiter, rp_instruction_delimiter)

        # Mona compensation
        if "|" in line and len(line.split("|")) > 3:
            continue
        line = line.replace(" :  ; ", ": ")
        line = re.sub(r"(\d+)H", r"0x\1", line)  # change format of hex
        line = line.replace("dword ptr ds:", "")
        line = line.replace("dword ptr fs:", "")
        line = line.replace("dword ptr", "")
        line = line.replace("byte ptr", "byte")
        line = line.replace("fs:0", "0")
        if "**" in line:
            line = line.split("**")[0]
        line = normal_retn.sub("ret", line)

        # Consistent commas
        line = normal_comams.sub(", ", line)

        # Consistent spacing
        line = normal_spaces.sub(" ", line)

        # Consistent gadget delimiters
        line = normal_delimiter.sub(rp_instruction_delimiter, line)

        # Remove ending
        line = rp_ending.sub("", line)

        # Cleanup zeros
        line = all_zeros.sub("0", line)
        line = null_ret.sub("ret", line)  #  retn 0x0000
        line = leading_zeros.sub("0x", line)

        split_addr = line.split(address_delimiter)
        address = split_addr[0].strip()
        instr = address_delimiter.join(split_addr[1:]).strip().lower()

        # Varname instruction
        varname = instr.upper().replace(" ", "").replace(";", "_").replace("[", "DEREF")
        varname = varname.replace("RETN", "").replace("_RET", "")
        for c in string.punctuation.replace("_", ""):
            varname = varname.replace(c, "")
        varname = varname.replace("LEAVE", "MOVESPEBP_POPEBP")
        varname = varname.replace("MOV", "MOV_")
        varname = varname.replace("XOR", "XOR_")
        varname = varname.replace("ADD", "ADD_")
        varname = varname.replace("SUB", "SUB_")
        varname = varname.replace("DEC", "DEC_")
        varname = varname.replace("INC", "INC_")
        varname = varname.replace("CALL", "CALL_")
        varname = varname.replace("JMP", "JMP_")
        varname = varname.replace("AND", "AND_")
        varname = varname.replace("NEG", "NEG_")
        varname = varname.replace("XCHG", "XCHG_")
        varname = varname.replace("INT3", "ROPBREAK")
        varname = varname.replace("RET", "ROPNOP")

        # Parse instructions and operands
        instr_list = instr.split(rp_instruction_delimiter)
        instr_list = [i.strip() for i in instr_list]
        instructions = []
        operands = find_reg.findall(instr)
        for i in instr_list:
            instructions.append(i.split(" ")[0])

        # Bad dereferences
        if "[0]" in instr:
            continue

        # Bad instructions
        rpre = "e" if args.winarch == "32" else "r"
        if "mov {}sp, {}bp".format(rpre, rpre) in instr:
            continue
        if "lea {}sp".format(rpre) in instr:
            continue
        # Remove if last instr is not retn
        if not instr_list[-1].startswith("ret"):
            continue

        gadget = {}
        gadget["addr"] = address
        gadget["instr"] = instr
        gadget["num_instr"] = len(instr_list) - 1
        gadget["instr_list"] = instr_list
        gadget["instructions"] = instructions
        gadget["operands"] = operands
        gadget["varname"] = varname
        gadgets.append(gadget)
        # log(gadget)
    log("[*] Found {} gadgets".format(len(gadgets)))

    # Filter gadgets
    gadgets_unique = []
    gadgets_filter = []
    for gadget in gadgets:
        # Filter - Bad characters
        if contains_bad_chars(gadget["addr"], args):
            continue
        # Filter - Large returns
        if large_return.search(gadget["instr"]):
            continue
        # Filter - Num instructions
        if gadget["num_instr"] > args.length:
            continue
        # Filter - First instruction
        if args.instr and args.instr != "all" and args.instr != gadget["instructions"][0]:
            continue
        # Filter - Last Instruction
        if args.instr_last and args.instr_last != "all" and args.instr_last != gadget["instructions"][-1]:
            continue
        # Filter - Operands
        if args.op1 and (len(gadget["operands"]) < 1 or gadget["operands"][0] != args.op1):
            continue
        if args.op2 and (len(gadget["operands"]) < 2 or gadget["operands"][1] != args.op2):
            continue
        if args.op3 and (len(gadget["operands"]) < 3 and gadget["operands"][2] != args.op3):
            continue

        # Unique
        if gadget["instr"] not in gadgets_unique:
            gadgets_unique.append(gadget["instr"])
            gadgets_filter.append(gadget)
    log("[*] Found {} unique gadgets".format(len(gadgets_filter)))

    return gadgets_filter


def search_gadget(gadgets, patterns):
    found_gadgets = []
    for gadget in gadgets:
        for pattern in patterns:
            if re.search("^" + pattern, gadget["instr"]):
                found_gadgets.append(gadget)
                break
    return found_gadgets


def categorize_gadgets(gadgets, args):
    """
    This function categorizes gadgets based on their intended use.
    The regex are sorted by "best" to "worst"
    """

    rpre = "e" if args.winarch == "32" else "r"

    output = {}

    # Special
    output["Break"] = search_gadget(gadgets, ["int3; ret"])
    output["NOP"] = search_gadget(gadgets, ["ret$", "retn 0$"])
    output["SEH PPR"] = search_gadget(
        gadgets,
        [
            "pop (?!{}sp|{}bp)(?:\w+); pop (?!{}sp|{}bp)(?:\w+); ret".format(rpre, rpre, rpre, rpre),
        ],
    )

    restore_stack = [
        "mov (?:...), {}sp ; .*".format(rpre),
        "push (?:{}sp) ; pop ... ;".format(rpre),
        "push (?:{}sp) ; (?:.+, .+|.+ .+) ; pop (?!{}sp)(?:...)".format(rpre, rpre),
        "jmp {}sp;".format(rpre),
        "leave;",
        "mov {}sp, ...;".format(rpre),
        "call {}sp;".format(rpre),
        "push (?!esp)(?:\w+); ?(?: \w+ \w+ ;)? pop esp; ?(?: \w+ \w+ ;)?",
        "pop esp; ?(?: \w+ \w+ ;)?; ret",
        "add esp, \w+;",
        "mov esp, ...; ?(?: \w+ \w+ ;)?",
        "xchg (..., esp|esp, ...); (?:.+, .+|.+ .+);",
    ]
    zeroize = []
    for reg in [
        "{}ax".format(rpre),
        "{}bx".format(rpre),
        "{}cx".format(rpre),
        "{}dx".format(rpre),
        "{}si".format(rpre),
        "{}di".format(rpre),
    ]:
        zeroize.append("xor {}, {};".format(reg, reg))
        zeroize.append("sub {}, {};".format(reg, reg))
        zeroize.append("(lea|mov|and) {}, 0;".format(reg))
        zeroize.append("(lea|mov|and) [{}], 0;".format(reg))
        restore_stack.append("xchg {}sp, {}; jmp {};".format(rpre, reg, reg))
        restore_stack.append("xchg {}sp, {}; call {};".format(rpre, reg, reg))

    output["Obtain SP"] = search_gadget(gadgets, ["mov (?:...), {}sp".format(rpre), "push (?:{}sp); pop ...".format(rpre), "push (?:{}sp); (?:.+, .+|.+ .+)".format(rpre)])
    output["Restore SP"] = search_gadget(gadgets, restore_stack)
    output["Load Values"] = search_gadget(gadgets, ["pop {}..;".format(rpre), "pop .*?;"])
    output["Load All Registers"] = search_gadget(gadgets, ["pushad;"])
    output["Register Swap"] = search_gadget(
        gadgets,
        [
            "mov {}.., {}..;".format(rpre, rpre),
            "xchg {}.., {}..;".format(rpre, rpre),
            "push {}..; pop {}..;".format(rpre, rpre),
            "push (?!{}sp)(?:...); pop (?!{}sp)(?:...)".format(rpre, rpre),
            "mov (?!{}sp)(?:...), ... ;?(?: \w+ \w+ ;)? ret".format(rpre),
            "lea ..., ...",
            "lea ..., \[.+\] ; (?:.+, .+|.+ .+) ret",
            "lea \[.+\], ... ; (?:.+, .+|.+ .+) ret",
            "xchg (?!{}sp)(?:...), (?!{}sp)(?:...) ; (?:.+, .+|.+ .+)".format(rpre, rpre),
            "pusha?.\s+; ret",
            "xchg (..., {}sp|{}sp, ...) ; (?:.+, .+|.+ .+)".format(rpre, rpre),
        ],
    )

    output["Add Values"] = search_gadget(gadgets, ["add ..., ...", "inc ...", "add .*?, .*?;", "inc .*?"])
    output["Subtract Values"] = search_gadget(gadgets, ["sub ..., ...", "dec ...", "sub .*?, .*?;", "dec .*?"])
    output["Zeroize"] = search_gadget(gadgets, zeroize)
    output["Negate"] = search_gadget(gadgets, ["neg {}..".format(rpre), "neg .*?;"])
    output["Memory Read"] = search_gadget(gadgets, ["mov .*?, \[.*?\];", "mov (?!esp)(?:...), \[(?!esp)(?:...)\] ; .* ret"])
    output["Memory Write"] = search_gadget(gadgets, ["mov \[.*?\], .*?;", "mov \[(?!esp)(?:...)\], (?!esp)(?:...) ; .* ret"])
    # output["Jump/Calls"] = search_gadget(gadgets, ["call \[...(?:\+|\-)0x.+\]", "call ...;", "jmp ...;", "jmp \[...(?:\+|\-)0x.+\]", "(jmp|call) {}sp;".format(rpre)])
    output["XOR"] = search_gadget(gadgets, ["xor {}.., ({}..|0x.+?);".format(rpre, rpre), "xor .*?;"])
    output["AND"] = search_gadget(gadgets, ["and {}.., ({}..|0x.+?);".format(rpre, rpre), "and .*?;"])

    # Sort all categories by size
    for cat in output:
        output[cat] = sorted(output[cat], key=lambda x: len(x["instr"]))

    return output


def print_gadgets(categories, args):
    """Print gadgets"""
    enable_color = platform.system() != "Windows" and not args.no_color
    GREEN = "\033[32m" if enable_color else ""
    NORMAL = "\033[0m" if enable_color else ""
    BLUE = "\033[34m" if enable_color else ""
    for category in categories:
        unique_instr = []
        gadgets = categories[category]
        log("{}# {} - {} gadgets{}".format(BLUE, category, len(gadgets), NORMAL))
        num_gadget = 0
        for gadget in gadgets:
            if num_gadget > args.printmax:
                break
            if len(gadget["varname"]) > 70:
                # Fixed size, way too long to be useful
                break
            if not args.dups and unique_instr and any([gadget["instr_list"][0] == i for i in unique_instr]):
                # Make sure no duplicates (i.e. ret vs retn 0x04)
                continue
            log("{:<70} = p32({}) {}# {}{}".format(gadget["varname"], gadget["addr"], GREEN, gadget["instr"], NORMAL))
            num_gadget += 1
            unique_instr.append(gadget["instr_list"][0])


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Finds and categorizes useful gadgets from files.")
    parser.add_argument(
        "-f",
        "--file",
        help="Space separated list of gadget files.",
        required=True,
        default=[],
        nargs="+",
    )
    parser.add_argument(
        "-wa",
        "--winarch",
        choices=["32", "64"],
        help="architecture of the given file (32=x86, 64=x864_64)",
        default="32",
    )
    parser.add_argument("-i", "--instr", help="Filter on first instruction")
    parser.add_argument("-o1", "--op1", help="Filter on 1st operand (register)")
    parser.add_argument("-o2", "--op2", help="Filter on 2nd operand (register)")
    parser.add_argument("-o3", "--op3", help="Filter on 3rd operand (register)")
    parser.add_argument("-il", "--instr-last", help="Filter on last instruction", choices=["all", "call", "ret", "retn", "jmp"], default="all")
    parser.add_argument("-a", "--aslr", help="Show all gadgets by base offset (ASLR bypass)", action="store_true")
    parser.add_argument("-d", "--dups", help="Show duplicates", action="store_true")
    parser.add_argument("-n", "--no-color", help="Disable color output", action="store_true")
    parser.add_argument("-p", "--printmax", help="Number of gadgets to print per category", type=int, default=20)
    parser.add_argument(
        "-b",
        "--bad",
        help="Hex bytes that are already known bad (ex: -b 00 0a 0d or -b 000a0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )
    parser.add_argument("-l", "--length", help="Max gadget length", type=int, choices=range(1, 11), default=5)
    parser.add_argument(
        "-o",
        "--output",
        help="Output file",
        default="gadgetizer.txt",
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, filename=args.output, filemode="w", format="%(message)s")
    log("[*] Output file: {}".format(args.output))

    # Parse bad characters
    args.bad = [b for bad in args.bad for b in bad]
    if args.bad and args.aslr:
        log("[-] ASLR - unable to properly check bad characters")
    if args.bad:
        bad_hexstr = " ".join("\\x{:02X}".format(i) for i in args.bad)
        if bad_hexstr:
            log("[*] BADCHARS: {}".format(bad_hexstr))

    # Loop input files
    gadgets = []
    for input_file in args.file:
        # Check file type passed in
        if is_binary_file(input_file):
            log("[*] Detected {} is binary. Running rp++".format(input_file))
            gadgets += run_rp(input_file, args)
        else:
            gadgets += read_file(input_file)

    # Clean/Filter gadgets
    gadgets = filter_gadgets(gadgets, args)

    # Categorize gadgets
    categories = categorize_gadgets(gadgets, args)

    # Print gadgets
    print_gadgets(categories, args)

    # Close the log file
    logging.shutdown()


if __name__ == "__main__":
    main()
    print("[*] Done!")
