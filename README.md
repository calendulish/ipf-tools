## IPF tools
You can use ipf.py to work with IPF archives. It can be used as a command-line tool with a `tar`-like syntax:

    usage: ipf.py [-h] [-t] [-x] [-m] [-c] [-f FILE] [-v] [-C DIR] [-r REVISION] [-b BASE_REVISION] [target]

    optional arguments:
      -h, --help               show this help message and exit
      -t, --list               list the contents of an archive
      -x, --extract            extract files from an archive
      -m, --meta               show meta information of an archive
      -c, --create             create archive from target      
      -f FILE, --file FILE     use archive file
      -v, --verbose            verbosely list files processed
      -C DIR, --directory DIR  change directory to DIR
      -r REVISION, --revision REVISION    revision number for the archive
      -b BASE_REVISION, --base-revision BASE_REVISION    base revision number for the archive  
      --enable-encryption      decrypt/encrypt when extracting/archiving
      --fnfilter FNFILTER      filename filter (eg *.lua)
      
In order to unpack an ipf file to the current directory, you can use:

    python ipf.py -xf target.ipf
    or python ipf.py -x -f target.ipf
    
You can also specify an output directory with `-C`:

    python ipf.py -xf target.ipf -C ./output/dir/
    
If you just want to find information about the file or list the archive contents, use `-m` and/or `-t`:

    python ipf.py -mtf target.ipf
    or python ipf.py -m -t -f target.ipf

You can provide filename filter to extract only specific files (e.g. only .lua files):

    python ipf.py --fnfilter "*.lua" -xf scripts.ipf

New archives can be created with `-c` (`--create`). The following command will create a new archive `test.ipf` with the contents of the folder `test`:

    python ipf.py -c -f test.ipf test
    
If you need to work with encrypted archives, use --enable-encryption flag:

    python ipf.py --enable-encryption -xf some_encrypted.ipf
    or python ipf.py --enable-encryption -cf new_encrypted.ipf test

Alternatively, `ipf.py` can be used as a library. The `IpfArchive` class handles all interactions with an IPF file. Opening and extracting all files from an archive is as easy as this:

    from ipf import IpfArchive
    
    ipf = IpfArchive('addon.ipf')
    ipf.open()
    ipf.extract_all('output/directory/')
    ipf.close()
    
You can extract certain files with the `get_data` method:

    f = open('extracted.bin', 'wb')
    f.write(ipf.get_data('map/map.lua'))
    f.close()

---
Lara Maia <dev@lara.click> 2017