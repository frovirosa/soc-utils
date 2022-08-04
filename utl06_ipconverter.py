#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author: Francesc Rovirosa Raduà - (copyright) Francesc Rovirosa 2022/febrer
# Aquest programa té drets d'autor, si voleu utilitzar-lo poseu-vos en contacte a l'adreça frovirosa@gmail.com
# https://github.com/frovirosa
#
# This utility is for testing on SSRF vulnerabilities. Also in WAF/IPS test evassion. Also, for fun and because I can ...

import sys
import ipaddress
import random
import socket
import argparse
import soc_lib.utils_lib as socutl


# VARS
__title__ = " FRR - For testing on SSRF vulnerabilities. Also WAF/IPS evassion."
__program__ = "utl06_ipconverter.py"
__package__ = "fr0viros4 SOC Tools/Utils"
__software__ = "FRR - Wind"
__version__ = u"1.2.10"
__author__ = "(c) 2022 Francesc Rovirosa Raduà, frovirosa@gmail.com - @fr0viros4 - https://github.com/frovirosa"
__doc__ = """
FRR-CSIRT/SOC Tools http://www.frovirosa.net by Francesc Rovirosa, fr0viros4 ||*|| - Free for Catalonia.
This program has not special requirements
"""

parser = argparse.ArgumentParser(description="Francesc Rovirosa - @fr0viros4. For testing on SSRF vulnerabilities. Also WAF/IPS evassion.", epilog="", prog=__program__)


def octalv2(byte2oct: int):
    return "0" * random.randint(1,9) + oct(byte2oct)[2:]


def domevassion(thearg):
    ip_list = []
    try:
        ip_list = list({addr[-1][0] for addr in socket.getaddrinfo(thearg, 0, 0, 0, 0)})
    except socket.gaierror as err:
        socutl.print_error_banner(str(err) + f"  -  Could not resolve \"{thearg}\"")
        sys.exit(-1)

    print("{: >32} - {}".format(socutl.onred("DOMAIN:", True), socutl.onwhite(thearg, True)))
    for oneip in ip_list:
        ipevassion(oneip)
        print("\n")


def ipevassion(thearg):
    stripnmb = thearg.split(".")
    intipnmb = list(map(int, stripnmb))
    myip = ""
    allforms = {"Decimal": "", "Class B": "", "Class A": "", "DWord": "", "HEX format 1": "", "HEX format 2": "", "HEX format 3": "", "HEX format 4": "", "Octal format 1": "", "Octal format 2": "", "Octal format 3": "",
                "URL encoded": "", "UNICODE": ""}
    try:
        myip = ipaddress.ip_address(thearg)
    except ValueError:
        socutl.print_error_banner(f"Error: {thearg} does not appear to be an IPv4 or IPv6 address. Exiting ...")

    allforms["Decimal"] = "http://" + thearg
    allforms["Class B"] = "http://" + ".".join([stripnmb[0], stripnmb[1], str(intipnmb[2] * 256 + intipnmb[3])])
    allforms["Class A"] = "http://" + ".".join([stripnmb[0], str(intipnmb[1] * 256 ** 2 + intipnmb[2] * 256 + intipnmb[3])])
    allforms["DWord"] = "http://" + str(int(myip))
    allforms["HEX format 1"] = "http://" + ".".join([hex(intipnmb[0]), hex(intipnmb[1]), hex(intipnmb[2]), hex(intipnmb[3])])
    allforms["HEX format 2"] = "http://" + hex(int(myip))
    allforms["HEX format 3"] = "http://" + hex(intipnmb[0]) + "." + hex(intipnmb[1] * 256 ** 2 + intipnmb[2] * 256 + intipnmb[3])
    allforms["HEX format 4"] = "http://" + hex(intipnmb[0]) + "." + hex(intipnmb[1]) + "." + hex(intipnmb[2] * 256 + intipnmb[3])
    allforms["Octal format 1"] = "http://" + ".".join(["0" + oct(intipnmb[0])[2:], "0" + oct(intipnmb[1])[2:], "0" + oct(intipnmb[2])[2:], "0" + oct(intipnmb[3])[2:]])
    allforms["Octal format 2"] = "http://" + ".".join([octalv2(intipnmb[0]), octalv2(intipnmb[1]), octalv2(intipnmb[2]), octalv2(intipnmb[3])])
    allforms["Octal format 3"] = "http://0" + "{0:o}".format(int(myip))
    allforms["URL encoded"] = "http://%" + "%".join("{:02x}".format(ord(c)) for c in thearg)
    allforms["UNICODE"] = u"For the future ... Printing UNICODE characters is not compatible with all terminal and consoles \U0001f62d"

    print("{: >32} - {}".format(socutl.onyellow("IP ENCODING:"), socutl.onwhite(thearg, True)))
    print("{: >32}{}".format(socutl.onwhite("============", True), socutl.onwhite("=" * 100, True)))
    for key, value in allforms.items():
        print("{: >32} - {}".format(socutl.ongreen(key), value))


def main(the_arguments):
    if the_arguments.ipconv:
        ipevassion(the_arguments.ipconv)
    else:
        domevassion(the_arguments.domconv)


if __name__ == "__main__":
    ttini = socutl.exec_header(None, prg_prg=__program__, prg_version=__version__, prg_title=__title__, prg_author=__author__, prg_package=__package__)
    g = parser.add_mutually_exclusive_group()
    g.add_argument("-i", "--ip", type=str, dest="ipconv", help="IP number in a numerical label format.", default=None)
    g.add_argument("-d", "--domain", type=str, dest="domconv", help="Domain to make evassion (it can be own more than one IP).", default=None)
    arguments = parser.parse_args()
    main(arguments)
    socutl.exec_footer(ttini)

