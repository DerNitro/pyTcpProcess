#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    Filename : pyTcpProcess.py
    Date: 08.04.2020 05:18
    Project: pyTcpProcess
    AUTHOR : Sergey Utkin
    EMAIL: utkins01@gmail.com
"""

import sys
import os
import json

__name__ = 'pyTcpProcess.py'
__version__ = 0.1

socket_file_list = [
    '/proc/net/tcp',
    '/proc/net/tcp6',
    '/proc/net/udp',
    '/proc/net/udp6'
]

state = {
    1: 'ESTABLISHED',
    2: 'SYN_SENT',
    3: 'SYN_RECV',
    4: 'FIN_WAIT1',
    5: 'FIN_WAIT2',
    6: 'TIME_WAIT',
    7: 'CLOSE',
    8: 'CLOSE_WAIT',
    9: 'LAST_ACK',
    10: 'LISTEN',
    11: 'CLOSING',
    12: 'NEW_SYN_RECV',
    13: 'MAX_STATES'
}


class IPv6:
    # Группы цифр в адресе разделяются двоеточиями (например, fe80:0:0:0:200:f8ff:fe21:67cf).
    # Незначащие старшие нули в группах могут быть опущены.
    # Большое количество нулевых групп может быть пропущено с помощью двойного двоеточия (fe80::200:f8ff:fe21:67cf).
    # Такой пропуск должен быть единственным в адресе.

    ip = ''   # type: str
    group_hex = []    # type: list

    def __init__(self, ip):
        for it in zip(*[iter(ip)] * 4):
            self.group_hex.append(''.join(it))
        for num in range(0, len(self.group_hex)):
            if int(self.group_hex[num], 16) == 0:
                self.group_hex[num] = '0'
            else:
                self.group_hex[num] = str(self.group_hex[num]).lstrip('0')
        flag = True
        for num in range(0, len(self.group_hex)):
            if self.group_hex[num] == '0' and flag:
                self.ip += ':'
                flag = False
            elif self.group_hex[num] == '0':
                pass
            else:
                self.ip += self.group_hex[num]
                if num != len(self.group_hex)-1:
                    self.ip += ':'
                flag = True
        if self.ip == ':':
            self.ip = '::'

    def get(self):
        return str(self.ip).lower()


class ProcessName:
    pid = None  # type: int
    name = None  # type: str
    uid = None  # type: int
    socket = None  # type: list
    path = None  # type: str

    def __init__(self, pid):
        self.pid = pid
        self.path = os.path.join('/proc/', pid)
        self.name = get_name(os.path.join(self.path, 'status'))
        self.uid = get_uid(os.path.join(self.path, 'status'))
        self.socket = []
        self.get_socket()

    def get_socket(self):
        fd_path = os.path.join(self.path, 'fd')
        if os.path.isdir(fd_path) and os.access(fd_path, os.R_OK):
            for fd in os.listdir(os.path.join(self.path, 'fd')):
                try:
                    read_link = os.readlink(os.path.join(fd_path, fd))
                except OSError:
                    read_link = ''
                if 'socket' in read_link:
                    read_link = int("".join([ch for ch in read_link if ch.isdigit()]))
                    self.socket.append(read_link)

    def get(self):
        return "{self.name}:{self.pid}".format(self=self)

    def __repr__(self):
        return str(self.__dict__)

    def __hash__(self):
        return int(self.pid)

    def __eq__(self, other):
        return int(self.pid) == int(other.pid)


class SocketConnect:
    number = None  # type: int
    local_ip = None  # type: str
    local_port = None  # type: int
    remote_ip = None  # type: str
    remote_port = None  # type: int
    state = None  # type: int
    type_socket = None  # type: str
    uid = None  # type: int
    inode = None  # type: int
    version = None  # type: int
    process = None  # type: ProcessName

    def __init__(self, parse):
        self.number = parse['number']
        self.local_ip, self.version = ip_hex2str(parse['local'].split(':')[0])
        self.local_port = int(parse['local'].split(':')[1], 16)
        self.remote_ip, self.version = ip_hex2str(parse['remote'].split(':')[0])
        self.remote_port = int(parse['remote'].split(':')[1], 16)
        self.state = state[int(parse['state'], 16)]
        self.uid = int(parse['uid'])
        self.inode = int(parse['inode'])

    def get(self):
        out = {
            'SrcAddr': self.local_ip,
            'SrcPort': self.local_port,
            'DstAddr': self.remote_ip,
            'DstPort': self.remote_port,
            'Proccess': self.process.get()
        }
        return out

    def __repr__(self):
        return str(self.__dict__)

    def __hash__(self):
        return int(self.inode)

    def __eq__(self, other):
        if isinstance(other, int):
            return int(self.inode) == int(other)
        else:
            return int(self.inode) == int(other.inode)


def parser_net(parse_line):
    out = {}
    parse_line = parse_line.split()
    out['number'] = parse_line[0].rstrip(':')
    out['local'] = parse_line[1]
    out['remote'] = parse_line[2]
    out['state'] = parse_line[3]
    out['uid'] = parse_line[7]
    out['inode'] = parse_line[9]
    if out['number'] == 'sl':
        return None
    return out


def ip_hex2str(ip):
    if len(ip) == 8:
        ver = 4
        temp_list = []
        for it in zip(*[iter(ip)] * 2):
            temp_list.append(''.join(it))
        return str('.'.join([str(int(it, 16)) for it in temp_list[::-1]])), ver
    else:
        ver = 6
        return IPv6(ip).get(), ver


def check_int(val):
    try:
        int(val)
        return True
    except ValueError:
        return False


def get_uid(path):
    try:
        if not os.path.isfile(path) or not os.access(path, os.R_OK):
            return None
        with open(path, 'r') as f:
            for read_line in f:
                if 'Uid:' in read_line:
                    return int(read_line.split()[1])
    except IOError:
        return None
    return None


def get_name(path):
    try:
        if not os.path.isfile(path) or not os.access(path, os.R_OK):
            return None
        with open(path, 'r') as f:
            for read_line in f:
                if 'Name:' in read_line:
                    return read_line.split()[1]
    except IOError:
        return None
    return None


if len(sys.argv) == 2 and sys.argv[1] in ('--help', '-h'):
    print(
        'Утилита сбора информации по TCP|UDP сессиям\n'
        '\trun: python pyTcpProcess.py'
        )
    sys.exit(0)
elif len(sys.argv) == 2 and sys.argv[1] in ('--version', '-v'):
    print('{}: {}'.format(__name__, __version__))
    sys.exit(0)

socket_list = []
for socket_file in socket_file_list:
    if not os.path.isfile(socket_file) or not os.access(socket_file, os.R_OK):
        break
    with open(socket_file, 'r') as s_file:
        for line in s_file:
            parse_result = parser_net(line.strip('\n'))
            if parse_result:
                socket_list.append(SocketConnect(parse_result))

process_list = []

for directory in os.listdir('/proc/'):
    if os.path.join('/proc', directory) and check_int(directory):
        process_list.append(ProcessName(directory))

active_socket = {}
for proc in process_list:
    for socket in proc.socket:
        if socket in socket_list:
            active_socket[socket] = proc

result = []
for socket in socket_list:
    if socket.inode in active_socket:
        socket.process = active_socket[socket.inode]
        result.append(socket)

print(json.dumps([i.get() for i in result if i.state in [state[1], state[10]]]))
sys.exit(0)
