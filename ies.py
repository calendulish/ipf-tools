#! /usr/bin/env python

import struct
import sys
import os
import zlib
import argparse
import csv
import glob

DEBUG = False

class IesFile(object):
    def __init__(self, name=None):

        self.name = name
        self.fullname = os.path.abspath(name)
        
        self.file_handle = open(self.name, 'rb')
        self.closed = False

        self.table_name = None
        self.columns = []
        self.rows = []

        self._open()    

    def close(self):
        if self.closed:
            return
        if self.file_handle:
            self.file_handle.close()
        self.closed = True

    def _decrypt_string(self, string):
        return ''.join(chr(ord(c) ^ 0x01) for c in string.strip('\x00'))

    def _open(self):
        self.table_name = self.file_handle.read(128).encode('utf-8')
        buf = self.file_handle.read(16)
        self._header_data = struct.unpack('<IIII', buf)

        self.data_offset = self._header_data[1]
        self.resource_offset = self._header_data[2]
        self.filesize = self._header_data[3]

        # data header
        buf = self.file_handle.read(12)
        self._data_header = struct.unpack('<HHHHHH', buf)
        self.row_count = self._data_header[1]
        self.column_count = self._data_header[2]
        self.int_column_count = self._data_header[3]
        self.string_column_count = self._data_header[4]

        if DEBUG:        
            print(self.column_count, 'columns')
            print(self.row_count, 'rows')
            print(self.int_column_count, 'integer columns')
            print(self.string_column_count, 'string columns')

        # go to columns
        self.file_handle.seek(-self.resource_offset - self.data_offset, 2)
        int_columns, str_columns = [], []
        for i in range(self.column_count):
            name1 = self._decrypt_string(self.file_handle.read(64))
            name2 = self._decrypt_string(self.file_handle.read(64))
            buf = self.file_handle.read(8)
            coltype, _, position = struct.unpack('<HIH', buf)
            # print('column', name1, 'type', ord(buf[0]))
            # print(['%02X' % ord(b) for b in buf])
            column = {'name': name1, 'name2': name2, 'type': coltype, 'position': position, 'unknown': _}
            if coltype == 0:
                int_columns.append(column)
            elif coltype in (1, 2):
                str_columns.append(column)

            if DEBUG:
                print(column)
            # self.columns.append(column)

        self.columns = sorted(int_columns, key=lambda c: c['position']) + sorted(str_columns, key=lambda c: c['position'])

        # go to rows
        # print('rows @', -self.resource_offset)
        if DEBUG:
            print([c['name'] for c in self.columns])
        self.file_handle.seek(-self.resource_offset, 2)

        for i in range(self.row_count):
            if DEBUG:
                print(self.file_handle.tell())
            row = []
            buf = self.file_handle.read(6)
            row_header = struct.unpack('<IH', buf)

            optional = row_header[1]
            self.file_handle.read(optional)
            for j in range(len(self.columns)):
                if self.columns[j]['type'] == 0:
                    # number
                    buf = self.file_handle.read(4)
                    floatval = struct.unpack('<f', buf)[0]
                    try:
                        intval = int(floatval)
                    except:
                        floatval = None

                    if floatval == intval:
                        row.append(intval)
                    else:
                        row.append(floatval)
                elif self.columns[j]['type'] in (1, 2):
                    # string
                    buf = self.file_handle.read(2)
                    length = struct.unpack('<H', buf)[0]

                    if length:
                        buf = self.file_handle.read(length)
                        string = self._decrypt_string(buf)
                        row.append(string)
                    else:
                        row.append('')
            self.file_handle.seek(self.string_column_count, 1)
            self.rows.append(row)

            if DEBUG:
                print(row)

    def write_csv(self, filename):
        f = open(filename, 'wb')
        writer = csv.writer(f)
        
        # write first line with columns
        f.write(','.join(c['name'] for c in self.columns))
        f.write('\n')

        # write rows
        for row in self.rows:
            writer.writerow(row)
        f.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Help: ./ies.py input_file(s) <output_directory>')
    else:
        if len(sys.argv) >= 3:
            out_dir = sys.argv[-1]
            if not os.path.isdir(out_dir):
                raise Exception('Invalid output directory: ' + out_dir)

            for arg in sys.argv[1:-2]:
                for filename in glob.glob(arg):
                    ies = IesFile(filename)
                    f = open(os.path.join(out_dir, filename + '.csv'), 'wb')
                    writer = csv.writer(f)
                    
                    f.write(','.join(c['name'] for c in ies.columns))
                    f.write('\n')
                    for row in ies.rows:
                        writer.writerow(row)
                    f.close()
                    ies.close()
        else:
            ies = IesFile(sys.argv[1])
            print([col['name'] for col in ies.columns])
            for row in ies.rows:
                print(row)

            print('Help: ./ies.py input_file(s) <output_directory>')

        ies.close()
