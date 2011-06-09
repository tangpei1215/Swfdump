#!/usr/bin/env python

import argparse
import ctypes
import sys
import re
import struct
import time
import os


class Swfdump:
    _SWF_HEADER_START = b'FWS'
    _SWF_FILE_VERSION = (9, 10, 11)

    def __init__(self, pid, min_size, max_size, directory):
        self.pid = int(pid)
        self.min_size = min_size
        self.max_size = max_size

        if not directory.startswith('/'):
            self.directory = '{0}/{1}'.format(os.getcwd(), directory)
        else:
            self.directory = directory
        self.swf_count = 0

    def dump(self):
        for region in self._memory_regions():
            data = self._read_region(region)
            swf = self._extract_swf(data)

        return self.swf_count, self.directory

    def _memory_regions(self):
        """Returns ranges of readable parts of pid's memory."""
        path = '/proc/{0}/maps'.format(self.pid)
        pattern = re.compile(r'([\dA-Fa-f]+)-([\dA-Fa-f]+) (r)')

        with open(path, 'r') as f:
            matches = [pattern.match(line) for line in f.readlines()]
            ranges = []
            for match in matches:
                if match is not None:
                    ranges.append((int(match.group(1), 16),
                            int(match.group(2), 16)))
        return ranges

    def _read_region(self, region):
        """Returns region chunk"""
        path = '/proc/{0}/mem'.format(self.pid)
        size = region[1] - region[0]

        with open(path, 'rb') as f:
            f.seek(region[0])
            return f.read(size)

    def _extract_swf(self, data):
        """Extract swf files from data chunk"""
        positions = [match.start() for match in
                re.finditer(re.escape(Swfdump._SWF_HEADER_START), data)]
        offset = 3
        for index in positions:
            version, length = struct.unpack('<BI',
                    data[index + offset: index + offset + 5])
            if version in Swfdump._SWF_FILE_VERSION:
                if (self.min_size <= length) and (self.max_size > length):
                    self._write_swf(data[index:index + length], version)
                    self.swf_count += 1

    def _write_swf(self, swf, version):
        """Writes the swf to a file"""
        path = '{0}/{1}-{2}.swf'.format(self.directory, version, len(swf))
        self._ensure_dir(path)
        with open(path, 'wb') as f:
            f.write(swf)

    def _ensure_dir(self, f):
        directory = os.path.dirname(f)
        if not os.path.exists(directory):
            os.makedirs(directory)


class Ptrace:
    _c_ptrace = ctypes.cdll.LoadLibrary('libc.so.6').ptrace
    _c_ptrace.argtypes = [ctypes.c_int, ctypes.c_int32,
            ctypes.c_void_p, ctypes.c_void_p]

    _PTRACE_ATTACH = ctypes.c_int(16)
    _PTRACE_DETACH = ctypes.c_int(17)

    def __init__(self, pid):
        self.pid = int(pid)

    def attach(self):
        c_pid = ctypes.c_int32(self.pid)
        error = Ptrace._c_ptrace(Ptrace._PTRACE_ATTACH, c_pid,
                ctypes.c_void_p(), ctypes.c_void_p())
        if error == -1:
            raise SystemError(error)

    def detach(self):
        c_pid = ctypes.c_int32(self.pid)
        error = Ptrace._c_ptrace(Ptrace._PTRACE_DETACH, c_pid,
                ctypes.c_void_p(), ctypes.c_void_p())
        if error == -1:
            raise SystemError(error)


def parse_args():
    parser = argparse.ArgumentParser(description='Dump swf files from memory.')
    parser.add_argument('pid', metavar='pid', type=int, help='process ID')
    parser.add_argument('--dir', dest='directory', default=os.getcwd(),
            help='use DIRECTORY as output directory')
    parser.add_argument('--min-size', dest='min_size', type=int, default=0,
            help='dump only files larger than MIN_SIZE (in KB)')
    parser.add_argument('--max-size', dest='max_size', type=int, default=sys.maxsize,
            help='dump only files smaler than MAX_SIZE (in KB)')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    ptrace = Ptrace(args.pid)
    try:
        ptrace.attach()
        time.sleep(1)
        #os.waitpid(args.pid, 0)
        swfdump = Swfdump(args.pid,
                args.min_size * 1024, args.max_size * 1024, args.directory)

        count, directory = swfdump.dump()
        if count == 0:
            print('0 files dumped')
        else:
            print('dumped {0} file(s) in {1}'.format(count, directory))

        ptrace.detach()
    except IOError:
        print('Failed to write to', args.directory)
    except OSError:
        print('os.waitpid({0}) failed'.format(args.pid))
    except SystemError:
        print('ptrace({0}) failed'.format(args.pid))
