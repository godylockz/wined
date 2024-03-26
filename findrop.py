#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""This WinDBG script is used to identify ROP gadgets.

Usage:
    0:010> !py \\tsclient\share\wined\findrop.py -m libspp -b 00 0a
"""

# Imports
import argparse
import os
import sys

try:
    import pykd
except ImportError:
    print("pykd module not available. Make sure you are running this script inside WinDBG.")
    sys.exit(1)

# Constants
MEM_ACCESS_EXE = {
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}
PAGE_SIZE = 0x1000
MAX_GADGET_SIZE = 8
BAD = [
    "clts",
    "hlt",
    "lmsw",
    "ltr",
    "lgdt",
    "lidt",
    "lldt",
    "mov cr",
    "mov dr",
    "mov tr",
    "in ",
    "ins",
    "invlpg",
    "invd",
    "out",
    "outs",
    "cli",
    "sti" "popf",
    "pushf",
    "int",
    "iret",
    "iretd",
    "swapgs",
    "wbinvd",
    "call",
    "jmp",
    "leave",
    "ja",
    "jb",
    "jc",
    "je",
    "jr",
    "jg",
    "jl",
    "jn",
    "jo",
    "jp",
    "js",
    "jz",
    "lock",
    "enter",
    "wait",
    "???",
]


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


def getModule(modname):
    """
    Return a module object.
    @param modname: string module name
    @return: pykd module object
    """
    return pykd.module(modname)


def isPageExec(address):
    """
    Return True if a mem page is marked as executable
    @param address: address in hex format 0x41414141.
    @return: Bool
    """
    try:
        protect = pykd.getVaProtect(address)
    except:
        protect = 0x1
    if protect in MEM_ACCESS_EXE.keys():
        return True
    else:
        return False


def findExecPages(mod):
    """
    Find Executable Memory Pages for a module.
    @param mod: module object returned by getModule
    @return: a python list of executable memory pages
    """
    pages = []
    pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
    print("[*] Total Memory Pages: {:d}".format(pn))
    for i in range(0, pn):
        page = mod.begin() + i * PAGE_SIZE
        if isPageExec(page):
            pages.append(page)
    print("[*] Executable Memory Pages: {:d}".format(len(pages)))
    return pages


def findRetn(pages):
    """
    Find all return instructions for the given memory pages.
    @param pages: list of memory pages
    @return: list of memory addresses
    """
    retn = []
    for page in pages:
        ptr = page
        while ptr < (page + PAGE_SIZE):
            b = pykd.loadSignBytes(ptr, 1)[0] & 0xFF
            if b not in [0xC3, 0xC2]:
                ptr += 1
                continue
            else:
                retn.append(ptr)
                ptr += 1

    print("[*] Found {:d} ret instructions".format(len(retn)))
    return retn


def formatInstr(instr, mod):
    """
    Replace address with modbase+offset.
    @param instr: instruction string from disasm.instruction()
    @param mod: module object from getModule
    @return: formatted instruction string: modbase+offset instruction
    """
    address = int(instr[0:8], 0x10)
    offset = address - mod.begin()
    return "{:s}+0x{:x}\t{:s}".format((mod.name(), offset, instr[9:]))


def disasmGadget(addr, mod, fp):
    """
    Find gadgets. Start from a ret instruction and crawl back from 1 to
    MAX_GADGET_SIZE bytes. At each iteration disassemble instructions and
    make sure the result gadget has no invalid instruction and is still
    ending with a ret.
    @param addr: address of a ret instruction
    @param mod: module object from getModule
    @param fp: file object to log found gadgets
    @return: number of gadgets found starting from a specific address
    """
    count = 0
    for i in range(1, MAX_GADGET_SIZE):
        gadget = []
        ptr = addr - i
        dasm = pykd.disasm(ptr)
        gadget_size = dasm.length()
        while gadget_size <= MAX_GADGET_SIZE:
            instr = dasm.instruction()
            if any(bad in instr for bad in BAD):
                break
            gadget.append(instr)
            if instr.find("ret") != -1:
                break
            dasm.disasm()
            gadget_size += dasm.length()
        matching = [i for i in gadget if "ret" in i]
        if matching:
            count += 1
            fp.write("-" * 86 + "\r\n")
            for instr in gadget:
                try:
                    fp.write(str(instr) + "\r\n")
                except UnicodeEncodeError:
                    print(str(repr(instr)))
    return count


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Searches for ROP gadgets by module name.")
    parser.add_argument(
        "-b",
        "--bad",
        help="Hex bytes that are already known bad (ex: -b 00 0a 0d or -b 000a0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )
    parser.add_argument("-m", "--modules", help="Module name(s) to search for ROP gadgets (ex: findppr.py libspp diskpls libpal)", nargs="+", default=[], required=True)
    parser.add_argument("-s", "--size", help="Max gadget size", type=int, default=5, required=False)
    parser.add_argument("-o", "--output", help="Output filename to user desktop", type=str, default="rop.txt", required=False)
    args = parser.parse_args()

    # Parse bad characters
    if args.bad:
        args.bad = [b for bad in args.bad for b in bad]
        bad_hexstr = " ".join("\\x{:02X}".format(i) for i in args.bad)
        if bad_hexstr:
            print("[*] Bad Characters: {}".format(bad_hexstr))

    # Open output file:
    output_file = os.path.join(os.path.expanduser("~"), "Desktop", args.output)
    fp = open(output_file, "w")

    count = 0
    for module in args.modules:
        mod = getModule(module)
        if mod:
            pages = findExecPages(mod)
            retn = findRetn(pages)
            if retn:
                print("[*] Gadget discovery started ...")
                for ret in retn:
                    count += disasmGadget(ret, mod, fp)
                print("[*] Found {:d} gadgets in {:s}.".format(count, mod.name()))
            else:
                print("[*] ret instructions not found!")

    # Close output file3
    print("[*] Output saved to {}".format(output_file))
    fp.close()


if __name__ == "__main__":
    main()
    print("[*] Done!")
