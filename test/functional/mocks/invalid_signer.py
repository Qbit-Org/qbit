#!/usr/bin/env python3
# Copyright (c) 2018-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import argparse
import json

def perform_pre_checks():
    mock_result_path = os.path.join(os.getcwd(), "mock_result")
    if os.path.isfile(mock_result_path):
        with open(mock_result_path, "r", encoding="utf8") as f:
            mock_result = f.read()
        if mock_result[0]:
            sys.stdout.write(mock_result[2:])
            sys.exit(int(mock_result[0]))

def enumerate(args):
    sys.stdout.write(json.dumps([{"fingerprint": "b3c19bfc", "type": "trezor", "model": "trezor_t"}]))

def getdescriptors(args):
    xpub_pkh = "qrpbSXj4PCoApjTY8T1qsyb3N5GoMowpzCYWgqsfFe7BE1hfsknLeMFfHXt81FeCrSPkCM4VUVi5MuRBTKNFgNdPdoikvabTyXcwAXwS3FbF5jW"
    xpub_sh = "qrpbSY6jt7K9MrKeFktmC9UYLsqPiL4ttmnhEKyzmWYAEmtXLSEyK2uzmfKLf1EtQGz5SwTrvAowXVCEiS4B53qBsRJhHbDD5tQ9HqHxYnGFwXT"
    xpub_wpkh = "qrpbSYmyQxoguT7bmxWVGo6Ekmka5vsRP3DZYQ6RR1SPmqMRiQiEW5Knt8UtWk2hHMKNnGF2wd5XXYNkkrwTn6x93ehUGq5TuFZbZRCKRPbFPE3"

    sys.stdout.write(json.dumps({
        "receive": [
            "pkh([b3c19bfc/44'/1'/" + args.account + "']" + xpub_pkh + "/0/*)#h26nxtl9",
            "sh(wpkh([b3c19bfc/49'/1'/" + args.account + "']" + xpub_sh + "/0/*))#32ry02yp",
            "wpkh([b3c19bfc/84'/1'/" + args.account + "']" + xpub_wpkh + "/0/*)#jftn8ppv"
        ],
        "internal": [
            "pkh([b3c19bfc/44'/1'/" + args.account + "']" + xpub_pkh + "/1/*)#x7ljm70a",
            "sh(wpkh([b3c19bfc/49'/1'/" + args.account + "']" + xpub_sh + "/1/*))#ytdjh437",
            "wpkh([b3c19bfc/84'/1'/" + args.account + "']" + xpub_wpkh + "/1/*)#rawj6535"
        ]
    }))

parser = argparse.ArgumentParser(prog='./invalid_signer.py', description='External invalid signer mock')
parser.add_argument('--fingerprint')
parser.add_argument('--chain', default='main')
parser.add_argument('--stdin', action='store_true')

subparsers = parser.add_subparsers(description='Commands', dest='command')
subparsers.required = True

parser_enumerate = subparsers.add_parser('enumerate', help='list available signers')
parser_enumerate.set_defaults(func=enumerate)

parser_getdescriptors = subparsers.add_parser('getdescriptors')
parser_getdescriptors.set_defaults(func=getdescriptors)
parser_getdescriptors.add_argument('--account', metavar='account')

if not sys.stdin.isatty():
    buffer = sys.stdin.read()
    if buffer and buffer.rstrip() != "":
        sys.argv.extend(buffer.rstrip().split(" "))

args = parser.parse_args()

perform_pre_checks()

args.func(args)
