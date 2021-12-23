#!/usr/bin/env python3

import os
import zipfile
import io
import argparse
import shutil

foundvulnerable = False
global_filenames = ''


# all credits for the original from https://github.com/CERTCC/CVE-2021-44228_scanner
# Install instructions :
#
# This script can be enabled for Mac, Windows and Linux platform
#
# Set Timeout to at least 2400 sec
# input set : Run by entry point -> run
# output : Auto Detect

def process_jarfile_content(zf, filetree):
    '''

    Recursively look in zf for the class of interest or more jar files
    Print the hits
    zf is a zipfile.ZipFile object
    '''
    global global_filenames
    ispatched = False
    hasjndi = False
    global foundvulnerable
    for f in zf.namelist():
        if os.path.basename(f) == 'JndiLookup.class':
            # found one, print it
            filetree_str = ' contains '.join(filetree)
            hasjndi = True
            jndilookupbytes = zf.read(f)
            if b'JNDI is not supported' in jndilookupbytes:
                # 2.12.2 is patched
                # https://github.com/apache/logging-log4j2/commit/70edc233343815d5efa043b54294a6fb065aa1c5#diff-4fde33b59714d0691a648fb2752ea1892502a815bdb40e83d3d6873abd163cdeR37
                ispatched = True
        elif os.path.basename(f) == 'MessagePatternConverter.class':
            mpcbytes = zf.read(f)
            if b'Message Lookups are no longer supported' in mpcbytes:
                # 2.16 is patched
                # https://github.com/apache/logging-log4j2/commit/27972043b76c9645476f561c5adc483dec6d3f5d#diff-22ae074d2f9606392a3e3710b34967731a6ad3bc4012b42e0d362c9f87e0d65bR97
                ispatched = True
        elif os.path.basename(f).lower().endswith(".jar") or os.path.basename(f).lower().endswith(".war") or os.path.basename(f).lower().endswith(".ear") or os.path.basename(f).lower().endswith(".zip"):
            # keep diving
            try:
                new_zf = zipfile.ZipFile(io.BytesIO(zf.read(f)))
            except:
                continue
            new_ft = list(filetree)
            new_ft.append(f)
            process_jarfile_content(new_zf, new_ft)
    if hasjndi and ispatched:
        print(filetree_str,'contains "JndiLookup.class" ** BUT APPEARS TO BE PATCHED **')
    elif hasjndi:
        foundvulnerable = True
        print("WARNING: ", filetree_str,'contains "JndiLookup.class"')
        global_filenames+=filetree_str + "\n"

def do_jarfile_from_disk(fpath):
    try:
        zf = zipfile.ZipFile(fpath)
    except:
        return
    process_jarfile_content(zf, filetree=[fpath,])


def main(topdir):
    global global_filenames

    output=""
    for root, dirs, files in os.walk(topdir, topdown=True):
        dirs[:] = filter(lambda dir: not os.path.ismount(os.path.join(root, dir)), dirs)
        for name in files:
            if not (name.lower().endswith('.jar') or name.lower().endswith('.war') or name.lower().endswith('.ear') or name.lower().endswith('.zip') or name.endswith('JndiLookup.class')):
                # skip non-jars
                continue
            if (os.path.basename(name) == "JndiLookup.class"):
                print("WARNING: %s *IS* JndiLookup.class" % os.path.join(root,name))
                global_filenames += os.path.join(root,name) + "\n"

            else:
                jarpath = os.path.join(root, name)
                do_jarfile_from_disk(jarpath)
    if not foundvulnerable:
        print("No vulnerable components found")
        return False
    else:
        return True

def run():
    global global_filenames

    all_tests=False

    if os.name =='nt':
        available_drives = ['%s:' % d for d in 'ABCDEFGHIJ' if os.path.exists('%s:' % d)]
        for drive in available_drives:
            drive=drive+"\\"
            print("Let's scan : " + drive)
            total, used, free = shutil.disk_usage(drive)
            print("Used: %d GiB" % (used // (2 ** 30)))
            if (main(drive)):
                all_tests=True
    elif os.name=='posix':
            drive="/"
            print("Let's scan : " + drive)
            total, used, free = shutil.disk_usage(drive)
            print("Used: %d GiB" % (used // (2 ** 30)))
            if (main(drive)):
                all_tests=True
    else:
        print("Error os.name returned :" + str(os.name))

    if (all_tests):
        return{'vulnerable': True, 'filenames': global_filenames}
    else:
        return{'vulnerable': False, 'filenames': ''}

