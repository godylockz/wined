#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This is a template used for fuzzing a process/service for a crash via boofuzz.

Usage:
- Terminal 1: py .\process_monitor.py
- Terminal 2: py fuzzerboo.py

References:
- https://epi052.gitlab.io/notes-to-self/blog/2020-05-14-osce-exam-practice-part-two/

Dependencies:
    pip install boofuzz
"""

# Imports
from boofuzz import *

tgt_ip = "192.168.0.218"
tgt_port = 9999  # vulnserver

# Logging
f = open("fuzz_logs.txt", "w")
loggers = [FuzzLoggerText(file_handle=f)]

# Start/Kill vulnserver
start_vulnserver = [["C:\\Users\\user\\Desktop\\vulnserver\\vulnserver.exe"]]
kill_vulnserver = [['powershell -c "stop-process -name vulnserver -force"']]
options = {"start_commands": start_vulnserver, "stop_commands": kill_vulnserver, "proc_name": "vulnserver.exe"}
procmon = ProcessMonitor(tgt_ip, 26002)
procmon.set_options(**options)
monitors = [procmon]

target = Target(connection=SocketConnection(tgt_ip, tgt_port, proto="tcp"), monitors=monitors)
session = Session(target=target, restart_interval=150, sleep_time=1, fuzz_loggers=loggers)

s_initialize("vulnserver-fuzzcase")  # arbitrary name for overall fuzz case

# fuzzing directives go here
# s_string("COMMAND TO FUZZ", fuzzable=False)  # change me
s_string("TRUN", fuzzable=False)
s_delim(" ", fuzzable=False)
s_string("something")

req = s_get("vulnserver-fuzzcase")

session.connect(req)

print(f"fuzzing with {req.num_mutations()} mutations")

session.fuzz()  # do the thing!
