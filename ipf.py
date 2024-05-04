#! /usr/bin/env python

import struct
import sys
import os
import zlib
import argparse
import fnmatch

from binascii import crc32
import crypt

SUPPORTED_FORMATS = (bytearray('\x50\x4b\x05\x06', 'utf-8'),)
UNCOMPRESSED_EXT = (".jpg", ".JPG", ".fsb", ".mp3")
UNENCRYPTED_EXT = UNCOMPRESSED_EXT # they happen to be same
CLIENT_PASSWORD = bytes([0x6F, 0x66, 0x4F, 0x31, 0x61, 0x30, 0x75, 0x65,
                         0x58, 0x41, 0x3F, 0x20, 0x5B, 0xFF, 0x73, 0x20,
                         0x68, 0x20, 0x25, 0x3F])

class IpfInfo(object):
    """
    This class encapsulates information about a file entry in an IPF archive.

    Attributes:
        filename: A string representing the path and name of the file.
        archivename: The name of the originating IPF archive.
        compressed_length: The length of the compressed file data.
        uncompressed_length: The length of the uncompressed file data.
        data_offset: Offset in the archive file where data for this file begins.
    """

    def __init__(self, filename=None, archivename=None, datafile=None):
        """
        Inits IpfInfo class.
        """
        self._filename_length = 0
        self._unknown1 = None
        self._compressed_length = 0
        self._uncompressed_length = 0
        self._data_offset = 0
        self._archivename_length = 0

        self._filename = filename
        self._archivename = archivename
        self.datafile = datafile

    @classmethod
    def from_buffer(self, buf):
        """
        Creates IpfInfo instance from a data buffer.
        """
        info = IpfInfo()
        data = struct.unpack('<HIIIIH', buf)

        info._filename_length = data[0]
        info._crc = data[1]
        info._compressed_length = data[2]
        info._uncompressed_length = data[3]
        info._data_offset = data[4]
        info._archivename_length = data[5]
        return info

    def to_buffer(self):
        """
        Creates a data buffer that represents this instance.
        """
        archivename = self.archivename.encode()
        filename = self.filename.encode()
        data = struct.pack('<HIIIIH', len(filename), self.crc, self.compressed_length, self.uncompressed_length, self.data_offset, len(archivename))
        data += archivename
        data += filename
        return data

    @property
    def filename(self):
        return self._filename

    @property
    def archivename(self):
        return self._archivename

    @property
    def compressed_length(self):
        return self._compressed_length

    @property
    def uncompressed_length(self):
        return self._uncompressed_length

    @property
    def data_offset(self):
        return self._data_offset

    @property
    def crc(self):
        return self._crc

    @property
    def key(self):
        return '{}_{}'.format(self.archivename.lower(), self.filename.lower())

    def supports_encryption(self):
        _, extension = os.path.splitext(self._filename)
        return extension not in UNENCRYPTED_EXT

class IpfArchive(object):
    """
    Class that represents an IPF archive file.
    """

    def __init__(self, name, verbose=False, revision=0, base_revision=0, enable_encryption=False):
        """
        Inits IpfArchive with a file `name`.

        Note: IpfArchive will immediately try to open the file. If it does not exist, an exception will be raised.
        """
        self.name = name
        self.verbose = verbose
        self.revision = revision
        self.base_revision = base_revision
        self.enable_encryption = enable_encryption
        self.fullname = os.path.abspath(name)
        _, self.archivename = os.path.split(self.name)
        
        self.file_handle = None
        self.closed = True

        self._files = None

    @property
    def files(self):
        if self._files is None:
            raise Exception('File has not been opened yet!')
        return self._files    

    def close(self):
        """
        Closes all file handles if they are not already closed.
        """
        if self.closed:
            return

        if self.file_handle.mode.startswith('w'):
            self._write()

        if self.file_handle:
            self.file_handle.close()
        self.closed = True

    def open(self, mode='rb'):
        if not self.closed:
            return

        self.file_handle = open(self.name, mode)
        self.closed = False
        self._files = {}

        if mode.startswith('r'):
            self._read()

    def _read(self):
        self.file_handle.seek(-24, 2)
        self._archive_header = self.file_handle.read(24)
        self._file_size = self.file_handle.tell()

        self._archive_header_data = struct.unpack('<HIHI4sII', self._archive_header)
        self.file_count = self._archive_header_data[0]
        self._filetable_offset = self._archive_header_data[1]

        self._filefooter_offset = self._archive_header_data[3]
        self._format = self._archive_header_data[4]
        self.base_revision = self._archive_header_data[5]
        self.revision = self._archive_header_data[6]

        if self._format not in SUPPORTED_FORMATS:
            raise Exception('Unknown archive format: {}'.format(repr(self._format)))

        # start reading file list
        self.file_handle.seek(self._filetable_offset, 0)
        for i in range(self.file_count):
            buf = self.file_handle.read(20)
            info = IpfInfo.from_buffer(buf)
            info._archivename = self.file_handle.read(info._archivename_length).decode()
            info._filename = self.file_handle.read(info._filename_length).decode()

            if info.key in self.files:
                # duplicate file name?!
                raise Exception('Duplicate file name: {}'.format(info.filename))

            self.files[info.key] = info

    def _write(self):
        pos = 0
        # write data entries first
        for key in self.files:
            fi = self.files[key]

            # read data
            f = open(fi.datafile, 'rb')
            data = f.read()
            f.close()

            fi._crc = crc32(data) & 0xffffffff
            fi._uncompressed_length = len(data)

            # check for extension
            _, extension = os.path.splitext(fi.filename)
            if extension in UNCOMPRESSED_EXT:
                # write data uncompressed
                fi._compressed_length = fi.uncompressed_length
            else:
                # compress data
                deflater = zlib.compressobj(6, zlib.DEFLATED, -15)
                data = deflater.compress(data)
                data += deflater.flush()
                fi._compressed_length = len(data)
                deflater = None

            if self.enable_encryption and fi.supports_encryption():
                data = crypt.encrypt(data, CLIENT_PASSWORD)

            self.file_handle.write(data)

            # update file info
            fi._data_offset = pos
            pos += fi.compressed_length

        self._filetable_offset = pos

        # write the file table
        for key in self.files:
            fi = self.files[key]
            buf = fi.to_buffer()
            self.file_handle.write(buf)
            pos += len(buf)

        # write archive footer
        buf = struct.pack('<HIHI4sII', len(self.files), self._filetable_offset, 0, pos, SUPPORTED_FORMATS[0], self.base_revision, self.revision)
        self.file_handle.write(buf)

    def get(self, filename, archive=None):
        """
        Retrieves the `IpfInfo` object for `filename`.

        Args:
            filename: The name of the file.
            archive: The name of the archive. Defaults to the current archive

        Returns:
            An `IpfInfo` instance that describes the file entry.
            If the file could not be found, None is returned.
        """
        if archive is None:
            archive = self.archivename
        key = '{}_{}'.format(archive.lower(), filename.lower())
        if key not in self.files:
            return None
        return self.files[key]

    def get_data(self, filename, archive=None):
        """
        Returns the uncompressed data of `filename` in the archive.

        Args:
            filename: The name of the file.
            archive: The name of the archive. Defaults to the current archive

        Returns:
            A string of uncompressed data.
            If the file could not be found, None is returned.
        """
        info = self.get(filename, archive)
        if info is None:
            return None
        self.file_handle.seek(info.data_offset)
        data = self.file_handle.read(info.compressed_length)

        if self.enable_encryption and info.supports_encryption():
            data = crypt.decrypt(data, CLIENT_PASSWORD)

        if info.compressed_length == info.uncompressed_length:
            return data
        return zlib.decompress(data, -15)

    def extract_all(self, output_dir, overwrite=False, fnfilter=None):
        """
        Extracts all files into a directory.

        Args:
            output_dir: A string describing the output directory.
        """
        for filename in self.files:
            if fnfilter and not fnmatch.fnmatch(filename, fnfilter):
                continue

            info = self.files[filename]
            output_file = os.path.join(output_dir, info.archivename, info.filename)

            if self.verbose:
                print('{}: {}'.format(info.archivename, info.filename))

            # print(output_file)
            # print(info.__dict__)
            if not overwrite and os.path.isfile(output_file):
                continue
            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            f = open(output_file, 'wb')
            try:
                data = self.get_data(info.filename, info.archivename)
                f.write(data)
            except Exception as e:
                print('Could not unpack {}'.format(info.filename))
                print(info.__dict__)
                print(e)
                print(data)
            f.close()

    def add(self, name, archive=None, newname=None):
        if archive is None:
            archive = self.archivename

        mode = 'Adding'
        fi = IpfInfo(newname or name, archive, datafile=name)
        if fi.key in self.files:
            mode = 'Replacing'
        if self.verbose:
            print('{} {}: {}'.format(mode, fi.archivename, fi.filename))
        self.files[fi.key] = fi


def print_meta(ipf, args):
    print('{:<15}: {:}'.format('File count', ipf.file_count))
    print('{:<15}: {:}'.format('Filetable', ipf._filetable_offset))
    print('{:<15}: {:}'.format('Unknown', ipf._archive_header_data[2]))
    print('{:<15}: {:}'.format('Archive header', ipf._filefooter_offset))
    print('{:<15}: {:}'.format('Format', repr(ipf._format)))
    print('{:<15}: {:}'.format('Base revision', ipf.base_revision))
    print('{:<15}: {:}'.format('Revision', ipf.revision))

def print_list(ipf, args):
    for k in ipf.files:
        f = ipf.files[k]
        print('{} _ {}'.format(f.archivename, f.filename))

        # crc check
        # data = ipf.get_data(k)
        # print('{} / {} / {}'.format(f.crc, crc32(data) & 0xffffffff, ''))

def get_norm_relpath(path, start):
    newpath = os.path.normpath(os.path.relpath(path, args.target))
    if newpath == '.':
        return ''
    return newpath

def create_archive(ipf, args):
    if not args.target:
        raise Exception('No target for --create specified')

    _, filename = os.path.split(ipf.name)

    if os.path.isdir(args.target):
        for root, dirs, files in os.walk(args.target):
            # strip target path
            path = get_norm_relpath(root, args.target)

            # get archivename
            archive = filename
            components = path.split(os.path.sep)
            if components[0].endswith('.ipf'):
                archive = components[0]

            if path.startswith(archive):
                path = path[len(archive) + 1:]
            
            for f in files:
                newname = '/'.join(path.replace('\\', '/').split('/')) + '/' + f
                ipf.add(os.path.join(root, f), archive=archive, newname=newname.strip('/'))

    elif os.path.isfile(args.target):
        # TODO: Calculate relative path and stuff
        ipf.add(args.target)
    else:
        raise Exception('Target for --create not found')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    # functions
    parser.add_argument('-t', '--list', action='store_true', help='list the contents of an archive')
    parser.add_argument('-x', '--extract', action='store_true', help='extract files from an archive')
    parser.add_argument('-m', '--meta', action='store_true', help='show meta information of an archive')
    parser.add_argument('-c', '--create', action='store_true', help='create archive from target')
    # options
    parser.add_argument('-f', '--file', help='use archive file')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbosely list files processed')
    parser.add_argument('-C', '--directory', metavar='DIR', help='change directory to DIR')
    parser.add_argument('-r', '--revision', type=int, help='revision number for the archive')
    parser.add_argument('-b', '--base-revision', type=int, help='base revision number for the archive')
    parser.add_argument('--enable-encryption', action='store_true', help='decrypt/encrypt when extracting/archiving')
    parser.add_argument('--fnfilter', type=str, help='filename filter (eg *.lua)')
    parser.add_argument('--overwrite', action='store_true', help='overwrite existing files')

    parser.add_argument('target', nargs='?', help='target file/directory to be extracted or packed')

    args = parser.parse_args()

    if args.list and args.extract:
        parser.print_help()
        print('You can only use one function!')
    elif not any([args.list, args.extract, args.meta, args.create]):
        parser.print_help()
        print('Please specify a function!')
    else:
        if not args.file:
            parser.print_help()
            print('Please specify a file!')
        else:
            ipf = IpfArchive(args.file, verbose=args.verbose, enable_encryption=args.enable_encryption)

            if not args.create:
                ipf.open()
            else:
                ipf.open('wb')

            if args.revision:
                ipf.revision = args.revision
            if args.base_revision:
                ipf.base_revision = args.base_revision

            if args.meta:
                print_meta(ipf, args)

            if args.list:
                print_list(ipf, args)
            elif args.extract:
                ipf.extract_all(args.directory or '.', fnfilter=args.fnfilter, overwrite=args.overwrite)
            elif args.create:
                create_archive(ipf, args)

            ipf.close()
