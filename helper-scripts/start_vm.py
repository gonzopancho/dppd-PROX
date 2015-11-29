#!/bin/env python2.7
# Copyright(c) 2010-2015 Intel Corporation.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import random
from os import system
from os import popen
import socket
from time import sleep
import json
import sys

# This script starts qemu with the CPU layout specified by the cores
# array below. Each element in the array represents a core. To enable
# hyper-threading (i.e. two logical cores per core), each element in
# the array should be an array of length two. The values stored inside
# the array define to which host cores the guest cores should be
# affinitized. All arguments of this script are passed to qemu
# directly. Porting an existing qemu command line setup to make use of
# this script requires removing the -smp parameters and -qmp
# parameters if those were used. These are built by the script based
# on the cores array.

# After successfully starting qemu, this script will connect through
# QMP and affinitize all cores within the VM to match cores on the
# host.

cores = []
for i in range(0,10):
    cores.append([i, i + 20]);

def build_mask(cores):
    ret = 0;
    for core in cores:
        for thread in core:
            ret += 1 << thread;
    return ret;

n_cores = len(cores);
n_threads = len(cores[0]);

mask = str(hex((build_mask(cores))))

smp_str = str(n_cores*n_threads)
smp_str += ",cores=" + str(n_cores)
smp_str += ",sockets=1"
smp_str += ",threads=" + str(n_threads)

qemu_cmdline = ""
qemu_cmdline += "taskset " + mask + " qemu-system-x86_64 -smp " + smp_str + " \\\n"
qemu_cmdline += " -qmp unix:/tmp/qmp-sock,server,nowait \\\n"

for a in sys.argv[1:]:
    qemu_cmdline += " " + a

if (system("pgrep qemu") == 0):
    print "Qemu already running"
    exit(-1);
ret = system(qemu_cmdline)
if (ret != 0):
    print "Failed to run qemu. Command line used was: "
    print qemu_cmdline
    exit(-1);
print "Qemu started"

retry = 0
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
while (retry < 10):
    try:
        s.connect("/tmp/qmp-sock")
        break;
    except:
        print "Failed to connect, retry (" + str(retry + 1) + ")"
    sleep(1);
    retry = retry + 1
print "Connected to qmp"

# skip info about protocol
dat = s.recv(100000)
# need to run qmp_capabilities before next command works
s.send("{\"execute\" : \"qmp_capabilities\" }")
dat = s.recv(100000)
# Get the PID for each guest core
s.send("{\"execute\" : \"query-cpus\"}")
dat = s.recv(100000)
a = json.loads(dat)["return"];

if (len(a) != n_cores*n_threads):
    print "Mismatch between number of vCPU reported by qmp and configuration"

print "VM cpu info seems correct (" + str(len(a)) + " Cores)"

if (n_threads == 1):
    idx = 0;
    for core in a:
        cm  = str(hex(1 << cores[idx][0]))
        pid = str(core["thread_id"])
        system("taskset -p " + cm + " " + pid + " > /dev/null")
        idx = idx + 1
elif (n_threads == 2):
    idx = 0;
    prev = 0;
    for core in a:
        cm  = str(hex(1 << cores[idx][prev]))
        pid = str(core["thread_id"])
        system("taskset -p " + cm + " " + pid + " > /dev/null")
        prev = prev + 1;
        if (prev == 2):
            idx = idx + 1;
            prev = 0
else:
    print "More than 2 threads per core (not implemented)"

print "Core pinning complete"
