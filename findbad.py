#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""This WinDBG script identifies bad characters at the address.

Usage:
    0:010> !py \\tsclient\share\wined\findbad.py --address esp+1 --bad 1d --start 1 --end 7f
    0:010> !py \\tsclient\share\wined\findbad.py -a 01a7745c -b 00 09 0a 0d 20

References:
- https://github.com/ksecurity45/osed-scripts-1/blob/main/findbad-chars-windbg.py
- https://github.com/epi052/osed-scripts/blob/main/findbad-chars.py
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


def find_bad_chars(args):
    # Print information about the search range and bad characters
    print("[*] Start: {}".format(args.start))
    print("[*] End: {}".format(args.end))
    print("[*] Bad Chars: {}".format(args.bad))

    # Initializations
    expected = [i for i in range(args.start, args.end + 1) if i not in args.bad]
    prev_bad = False
    char_counter = 0
    new_bad = list()

    # Execute the debugger command and get the result
    command = "db {} L 0n{}".format(args.address, len(expected))
    result = pykd.dbgCommand(command)
    # print(result)
    if result is None:
        print("[!] Ran '{}', but received no output; exiting...".format(command))
        raise SystemExit

    # Parse the memory dump line into an object
    print("[*] Parsing memory dump ...")
    for line in result.splitlines():
        parts = line.split("  ")[:2]  # Discard the ascii portion right away
        if len(parts) == 0:
            continue
        # Join the bytes with spaces, handling the hyphen separator between the 8th and 9th byte
        bytes_str = " ".join(part.replace("-", " ") for part in parts[1].split())
        # Pass to the setter as a space-separated string of hex bytes for further processing/assignment
        bytes = [int(b, 16) for b in bytes_str.split()]

        # Compare each byte in the memory dump with the expected characters
        for byte in bytes:
            if byte != expected[char_counter] and not prev_bad:
                prev_bad = True
                new_bad.append(expected[char_counter])
                print("??".format(byte)),
            else:
                prev_bad = False
                print("{:02X}".format(byte)),
            char_counter += 1
        print("")

    # Print the list of newly found bad characters
    if new_bad:
        expected = ",".join(["0x{:02x}".format(x) for x in new_bad])
        print("[+] Bad chars: {}\n".format(expected))
    else:
        print("[+] No bad characters found")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-s",
        "--start",
        help="Hex byte from which to start searching in memory (default: 00)",
        default=[0],
        type=hex_byte,
    )
    parser.add_argument(
        "-e",
        "--end",
        help="Last hex byte to search for in memory (default: ff)",
        default=[255],
        type=hex_byte,
    )
    parser.add_argument(
        "-b",
        "--bad",
        help="Hex bytes that are already known bad (ex: -b 00 0a 0d or -b 000a0d)",
        nargs="+",
        type=hex_byte,
        default=[],
    )
    parser.add_argument("-a", "--address", help="Address from which to begin character comparison", required=True)
    args = parser.parse_args()

    # Parse bad characters
    if args.bad:
        args.bad = [b for bad in args.bad for b in bad]
        bad_hexstr = " ".join("\\x{:02X}".format(i) for i in args.bad)
        if bad_hexstr:
            print("[*] Bad Characters: {}".format(bad_hexstr))

    if not args.start or len(args.start) != 1:
        print("[!] --start value must be 00 through ff...")
        raise SystemExit
    if not args.end or len(args.end) != 1:
        print("[!] --end value must be 00 through ff...")
        raise SystemExit
    elif args.start > args.end:
        print("[!] --start value must be higher than --end; exiting...")
        raise SystemExit
    if args.address is None:
        print("[!] --address not set; exiting...")
        raise SystemExit

    args.start = args.start[0]
    args.end = args.end[0]

    find_bad_chars(args)


if __name__ == "__main__":
    main()
    print("[*] Done!")
