# Windows Exploitation (wined) Tools

The following scripts were used to automate Windows x86 (32-bit) / x86_64 (64-bit) Exploitation Development.

Feel free to submit issues/pull requests if you find anything wrong or want to improve!

## Development Environment

- [attach.ps1](attach.ps1) : Respawn services/processes, wait for sockets, and attach to WinDBG
- [getinstalls.sh](getinstalls.sh) : Get installations to be used during install.ps1
- [install.ps1](install.ps1) : Install Python, Mona, etc. to the target

## Automation Scripts (Python 2/3)

- [gadgetizer.py](gadgetizer.py) : Used to find ROP gadgets via RP++, and filter bad characters.
- [shellcoder.py](shellcoder.py) : Used to generate bad character/null-byte free position-independent shellcode.

WinDBG Scripts (Python 2/3)

- [findbad.py](findbad.py) : Identify a bad character array
- [findcave.py](findbad.py) : Identify a codecave (an executable memory region of a binary)
- [findiat.py](findiat.py) : Identify a function IAT
- [findppr.py](findppr.py) : Identify a Pop-Pop-Ret instruction
- [findrop.py](findrop.py) : Find ROP gadgets
- [search.py](search.py) : Intuitive search for ascii or specific bytes

## Templates

Various templates that can be use during exploitation.

- [template_exploit.py](template_exploit.py) : Exploit
- [template_fuzzer.py](template_fuzzer.py) : Fuzzing
- [template_fuzzerboo.py](templatefuzzerboo.py) : Fuzzing with boofuzz
