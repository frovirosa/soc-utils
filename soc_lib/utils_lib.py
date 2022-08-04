#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   FRR QRadar-Offenses
#
#   Copyright (c)2018 Francesc Rovirosa @frovirosez

import sys
import os
import time
from datetime import datetime
import json
import collections
import urllib.parse
from termcolor import cprint
from pyfiglet import figlet_format
from colorama import Fore, Back, Style, init
from ascii_graph import Pyasciigraph
from ascii_graph.colors import *
from ascii_graph.colordata import hcolor
from prettytable import PrettyTable
from textwrap import wrap

__program__ = "---"
__package__ = "fr0viros4 SOC Tools"
__software__ = "---"
__version__ = u"0.0.0"
__author__ = "(c) 2022 Francesc Rovirosa, frovirosa@gmail.com - @fr0viros4"
__doc__ = """
FRR-SOC Tools http://www.frovirosa.net
by Francesc Rovirosa, froVirosez ||*|| - Catalonia independent.
This program has not special requirements. Python >= 3.7
"""
tini = 0
VAL_WRAP_WIDTH = 60
VAL_WRAP_MID_WIDTH = 80
VAL_WRAP_WIDTH_EXT = 120
MAX_ABUSECONFIDENCE_SCORE = 50
abtypes = {3: ["Fraud Orders", "Fraudulent orders."], 4: ["DDoS Attack", "Participating in distributed denial-of-service (usually part of botnet)."],
           5: ["FTP Brute-Force", ""], 6: ["Ping of Death", "Oversized IP packet."], 7: ["Phishing", "Phishing websites and/or email."], 8: ["Fraud VoIP", ""],
           9: ["Open Proxy", "Open proxy, open relay, or Tor exit node."], 10: ["Web Spam", "Comment/forum spam, HTTP referer spam, or other CMS spam."],
           11: ["Email Spam", "Spam email content, infected attachments, and phishing emails. Note: Limit comments to only relevent information (instead "
                "of log dumps) and be sure to remove PII if you want to remain anonymous."], 12: ["Blog Spam", "CMS blog comment spam."],
           13: ["VPN IP", "Conjunctive category."], 14: ["Port Scan", "Scanning for open ports and vulnerable services."], 15: ["Hacking", ""],
           16: ["SQL Injection", "Attempts at SQL injection."], 17: ["Spoofing", "Email sender spoofing."],
           18: ["Brute-Force", "Credential brute-force attacks on webpage logins and services like SSH, FTP, SIP, SMTP, RDP, etc. This category is seperate "
                               "from DDoS attacks."],
           19: ["Bad Web Bot", "Webpage scraping (for email addresses, content, etc) and crawlers that do not honor robots.txt. Excessive requests and user "
                               "agent spoofing can also be reported here."],
           20: ["Exploited Host", "Host is likely infected with malware and being used for other attacks or to host malicious content. The host owner may "
                                  "not be aware of the compromise. This category is often used in combination with other attack categories."],
           21: ["Web App Attack", "Attempts to probe for or exploit installed web applications such as a CMS like WordPress/Drupal, e-commerce solutions, "
                                  "forum software, phpMyAdmin and various other software plugins/solutions."],
           22: ["SSH", "Secure Shell (SSH) abuse. Use this category in combination with more specific categories."],
           23: ["IoT Targeted", "Abuse was targeted at an \"Internet of Things\" type device. Include information about what type of device was targeted "
                                "in the comments."]}

rcodes = {"201": "A new Ariel search was successfully created.",
          "409": "The search cannot be created. The requested search ID that was provided in the query expression is already in use. Please use a unique "
                 "search ID (or allow one to be generated).",
          "422": "The query_expression contains invalid AQL syntax.",
          "500": "An error occurred during the attempt to create a new search.",
          "503": "The Ariel server might be temporarily unavailable or offline. Please try again later."
          }


def color_field(cfield="", fc=None, bc=None):
    fcolors = {"NWHI": Fore.WHITE, "NBLU": Fore.BLUE, "NGRE": Fore.GREEN, "NRED": Fore.RED, "NYEL": Fore.YELLOW, "NMAG": Fore.MAGENTA, "NBLK": Fore.BLACK, "NCYA": Fore.CYAN,
               "BWHI": Fore.LIGHTWHITE_EX, "BBLU": Fore.LIGHTBLUE_EX, "BGRE": Fore.LIGHTGREEN_EX, "BRED": Fore.LIGHTRED_EX, "BYEL": Fore.LIGHTYELLOW_EX,
               "FMAG": Fore.LIGHTMAGENTA_EX, "FCYA": Fore.LIGHTCYAN_EX}
    bcolors = {"NWHI": Back.WHITE, "NBLU": Back.BLUE, "NGRE": Back.GREEN, "NRED": Back.RED, "NYEL": Back.YELLOW, "NMAG": Back.MAGENTA, "NBLK": Back.BLACK, "NCYA": Back.CYAN,
               "BWHI": Back.LIGHTWHITE_EX, "BBLU": Back.LIGHTBLUE_EX, "BGRE": Back.LIGHTGREEN_EX, "BRED": Back.LIGHTRED_EX, "BYEL": Back.LIGHTYELLOW_EX,
               "FMAG": Back.LIGHTMAGENTA_EX, "FCYA": Back.LIGHTCYAN_EX}

    ss = ""
    if fc:
        ss = "{}{}{}".format(fcolors[fc], cfield, Fore.RESET)
    elif bc:
        ss = "{}{}{}".format(bcolors[bc], ss, Back.RESET)

    return ss


def epoc_to_time(epoct, abbr=False):
    sec, milisec = divmod(epoct, 1000)
    if abbr:
        return '{}'.format(time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(epoct)))
    return '{}.{:03d}'.format(time.strftime('%Y/%m/%d %H:%M:%S', time.gmtime(sec)), milisec)


def datetime_from_file(fname=""):
    if not os.path.isfile(fname):
        return f"ERROR: File {fname} not exists"
    file_info = os.lstat(fname)
    return epoc_to_time(int(file_info.st_mtime), True)


def exec_header(additional=None, prg_prg=None, prg_version=None, prg_title=None, prg_author=None, prg_package=None):
    global __program__, __software__, __version__, __author__, __package__

    if sys.version_info[0] == 2:
        print("PYTHON 3.7 OR HIGHER IS REQUIRED ...\n")
        sys.exit(-1)

    if prg_prg is not None:
        __software__ = prg_prg
    if prg_version is not None:
        __version__ = prg_version
    if prg_title is not None:
        __program__ = prg_title
    if prg_author is not None:
        __author__ = prg_author
    if prg_package is not None:
        __package__ = prg_package
    init(strip=not sys.stdout.isatty())     # strip colors if stdout is redirected
    print("")
    # cprint(figlet_format(__package__, font="larry3d", width=1000), "green", on_color="on_white", attrs=["bold"])
    cprint(figlet_format(__package__, font="big", width=200), "green", attrs=["bold"])
    if additional:
        cprint(figlet_format(additional, font="digital", width=200), "green", attrs=["bold"])
    print(Style.RESET_ALL + Fore.LIGHTGREEN_EX + Style.BRIGHT + "- {}\nProgram: {} - {} - {}".format(__program__, __software__, __version__, __author__) + Style.RESET_ALL)
    print(Fore.LIGHTWHITE_EX + Style.BRIGHT + "{:%Y/%m/%d %H:%M}".format(datetime.now()) + Style.RESET_ALL)
    print("")
    return time.time()


def exec_footer(ttini=time.time()):
    print("\n\n")
    print(Fore.LIGHTWHITE_EX + "Elapsed time: {} seconds".format(round(float(time.time() - ttini), 3)) + Style.RESET_ALL)
    print("=" * 100)


def print_error_banner(error_banner):
    print("\n" + Back.RED + Fore.LIGHTWHITE_EX + error_banner + " " * (100 - len(error_banner)) + Style.RESET_ALL)
    print(Fore.LIGHTWHITE_EX + "=" * 100 + Style.RESET_ALL + "\n")


def print_api_title(apititle):
    print("\n" + Back.BLUE + Fore.LIGHTWHITE_EX + apititle + Style.RESET_ALL)
    print(Fore.LIGHTWHITE_EX + "=" * len(apititle) + Style.RESET_ALL + "\n")


# This function prints out the response from an endpoint in a consistent way.
def pretty_print_response(response):
    print(response.code)
    parsed_response = json.loads(response.read().decode('utf-8'))
    print(json.dumps(parsed_response, indent=4))
    return


def print_resume_eps(sumdne, sumeps, mm):
    print("\n" + Style.RESET_ALL + Fore.LIGHTWHITE_EX + "Total Events (in the last {} min.): ".format(mm) + Fore.LIGHTGREEN_EX + "{:,}".format(sumdne) +
          Fore.LIGHTWHITE_EX + "\nAverage EPS (Events per second in the last {} min.): ".format(mm) + Fore.LIGHTGREEN_EX + "{:,}".format(sumeps) + Style.RESET_ALL)


def print_asciigraph_eps(thedata):
    thresholds = {2000: BGre, 2500: BCya, 3500: BYel, 4500: BRed}
    gdata = hcolor(thedata, thresholds)
    maxval = int(thedata[0][1]) + 40

    graph = Pyasciigraph(
        line_length=120,
        min_graph_length=50,
        separator_length=2,
        multivalue=False,
        human_readable='yes',
        graphsymbol=u'■',
        float_format='{0:,.2f}',
        # force_max_value=1300,
        force_max_value=maxval,
    )

    print("\n{}[{} - {} - {} - {}]".format("Graph EPS Thresholds: ", ongreen("<= 2000"), oncyan("<= 2500"), onyellow("<= 3500"), onred(">= 4500")), end="")
    for line in graph.graph(label="", data=gdata):
        print(line)


def print_program_not_finished():
    cprint(figlet_format("MEN AT WORK !!!!", font="big", width=200), "red", attrs=["bold"])


def bggreen(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Back.LIGHTGREEN_EX + str(smsg) + Style.RESET_ALL
    return Back.GREEN + str(smsg) + Style.RESET_ALL


def bgyellow(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Back.LIGHTYELLOW_EX + str(smsg) + Style.RESET_ALL
    return Back.YELLOW + str(smsg) + Style.RESET_ALL


def bgcyan(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Back.LIGHTCYAN_EX + str(smsg) + Style.RESET_ALL
    return Back.CYAN + str(smsg) + Style.RESET_ALL


def bgred(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Back.LIGHTRED_EX + str(smsg) + Style.RESET_ALL
    return Back.RED + str(smsg) + Style.RESET_ALL


def bgmagenta(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Back.LIGHTMAGENTA_EX + str(smsg) + Style.RESET_ALL
    return Back.MAGENTA + str(smsg) + Style.RESET_ALL


def bgblue(smsg, bright=False, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Back.LIGHTBLUE_EX + str(smsg) + Style.RESET_ALL
    return Back.BLUE + str(smsg) + Style.RESET_ALL


def bgwhite(smsg, bright=False, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Back.LIGHTWHITE_EX + str(smsg) + Style.RESET_ALL
    return Back.WHITE + str(smsg) + Style.RESET_ALL


def bgblack(smsg, bright=False, outreport=False):
    if outreport:
        return smsg
    return Back.WHITE + str(smsg) + Style.RESET_ALL


def ongreen(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTGREEN_EX + str(smsg) + Style.RESET_ALL
    return Fore.GREEN + str(smsg) + Style.RESET_ALL


def onyellow(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTYELLOW_EX + str(smsg) + Style.RESET_ALL
    return Fore.YELLOW + str(smsg) + Style.RESET_ALL


def oncyan(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTCYAN_EX + str(smsg) + Style.RESET_ALL
    return Fore.CYAN + str(smsg) + Style.RESET_ALL


def onred(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTRED_EX + str(smsg) + Style.RESET_ALL
    return Fore.RED + str(smsg) + Style.RESET_ALL


def onmagenta(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTMAGENTA_EX + str(smsg) + Style.RESET_ALL
    return Fore.MAGENTA + str(smsg) + Style.RESET_ALL


def onblue(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTBLUE_EX + str(smsg) + Style.RESET_ALL
    return Fore.BLUE + str(smsg) + Style.RESET_ALL


def onwhite(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTWHITE_EX + str(smsg) + Style.RESET_ALL
    return Fore.WHITE + str(smsg) + Style.RESET_ALL


def onblack(smsg, bright=True, outreport=False):
    if outreport:
        return smsg
    if bright:
        return Fore.LIGHTBLACK_EX + str(smsg) + Style.RESET_ALL
    return Fore.BLACK + str(smsg) + Style.RESET_ALL


# this function prints out information about a request that will be made
# to the API.
def pretty_print_request(client, path, method, headers=None):
    ip = client.get_server_ip()
    base_uri = client.get_base_uri()

    header_copy = client.get_headers().copy()
    if headers is not None:
        header_copy.update(headers)

    url = "https://" + ip + base_uri + path
    method = Fore.LIGHTRED_EX + method + Style.RESET_ALL
    print("Sending a " + Style.BRIGHT + method + Style.NORMAL + " request to: " + Fore.LIGHTGREEN_EX + urllib.parse.unquote(url) + Style.RESET_ALL)
    # print(url)
    # print(urllib.parse.unquote(url))
    print("With these " + Fore.LIGHTRED_EX + "headers" + Style.RESET_ALL + ":")
    # print(header_copy)
    for header in header_copy:
        if header != "SEC":
            print("  - " + header + ": " + Fore.LIGHTYELLOW_EX + header_copy[header] + Style.RESET_ALL)
    print("")


def print_search_id(sid=None, qstring=""):
    print("Search ID: " + Fore.LIGHTWHITE_EX + sid + Fore.RESET)
    print("Query Str: " + Fore.YELLOW + qstring + Fore.RESET + "\n")


def print_query_string(qstring=None):
    print(": " + Back.LIGHTWHITE_EX + Fore.BLACK + qstring + Back.RESET + Style.RESET_ALL + "\n")


def print_error_line(err1="", err2=""):
    print("\n" + Style.RESET_ALL + Fore.LIGHTRED_EX + "{}: {}".format(err1, err2) + Style.RESET_ALL)


def initial_time():
    return time.time()


def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield cursor


def url_encode_value(vurl=""):
    return urllib.parse.quote(vurl)


####################################################################
# START FUNCTIONS FROM REPUTATION
def check_cachefile_exists(cachefile=""):
    if not os.path.isfile(cachefile):
        return False
    return True


def check_cachefile_is_valid(cachefile="", maxcacheitem=0):
    if not os.path.isfile(cachefile):
        return False
    cachefile_info = os.lstat(cachefile)
    if (int(cachefile_info.st_mtime) + maxcacheitem) < (int(time.time())):
        return False

    return True


def util_print_abuseipdb_endpoint_simple(data=None, is_cached=False, api_url=None):
    if api_url is None:
        api_url = "None => This IP is in local cache."

    print("{}\n{}\n{}".format(onmagenta("*" * 120), onmagenta("Abuse IPDB: -> URL: " + api_url), onmagenta("*" * 120)))

    print("{}AbuseIPDB (https://www.abuseipdb.com/) is a project dedicated to helping combat the spread of hackers, spammers, and abusive "
          "activity on the internet{}".format(Fore.LIGHTWHITE_EX + Style.BRIGHT, Style.RESET_ALL))

    if is_cached:
        print("{}IP Abuse Report for: {} - ({}){}\n{}".format(Fore.LIGHTGREEN_EX, data["ipAddress"], "This IP is in local cache !!", Style.RESET_ALL, "=" * 120))
    else:
        print("{}IP Abuse Report for; {}{}\n{}".format(Fore.LIGHTGREEN_EX, data["ipAddress"], Style.RESET_ALL, "=" * 120))

    print("{}IP Address            :{} {} (IPv{})".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, data["ipAddress"], data["ipVersion"]))
    abcs = data["abuseConfidenceScore"]
    hred = round((abcs * MAX_ABUSECONFIDENCE_SCORE) / 100)
    hwhite = MAX_ABUSECONFIDENCE_SCORE - hred
    print("{}Abuse confidence score:{} [{}{}{}{}{}] {}%".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, Fore.LIGHTRED_EX, "#" * hred, Fore.WHITE,
                                                                "·" * hwhite, Fore.LIGHTWHITE_EX, abcs))
    print("{}Is public             :{} {}".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, data["isPublic"],))
    print("{}Is whitelisted        :{} {}".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, data["isWhitelisted"]))
    print("{}Country code / name   :{} {} / {}".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, data["countryCode"], data["countryName"]))
    print("{}ISP / Domain          :{} {} / {}".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, data["isp"], data["domain"]))
    print("{}Usage type            :{} {}".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, data["usageType"]))
    print("\n\t+ {} Distinct users have reported in: {} reports.".format(data["numDistinctUsers"], data["totalReports"]))
    print("\t+ Last reported in: {}{}".format(data["lastReportedAt"], Style.RESET_ALL))
    print("\n")


def util_print_abuseipdb_endpoint_ext(data=None, ip="0.0.0.0"):
    sorted_data = collections.OrderedDict(sorted(data.items(), key=lambda kv: kv[1], reverse=True))
    t = PrettyTable(["# Citations", "Category name", "Description"])
    t.align = "l"
    for (key, value) in sorted_data.items():
        wrap_line = wrap(str(abtypes[key][1]) or "", VAL_WRAP_WIDTH_EXT) or [""]
        t.add_row([value, abtypes[key][0], wrap_line[0]])
        for subseq in wrap_line[1:]:
            t.add_row(["", "", subseq])

    if len(sorted_data) > 0:
        print("\n{}IP Abuse Reports for {} -> Involved categories{}\n{}".format(Fore.LIGHTGREEN_EX, ip, Style.RESET_ALL, "=" * 120))
        print(t)
    print(f"{'▀' * 120}\n\n\n")


def key_virustotal_report(dd):
    i = j = p = 0
    for items in dd:
        i += items["total"]
        p += items["positives"]
        j += 1
    return i, j, p


def util_print_virustotal_report(data, theip, is_cached=False, api_url=None):
    if api_url is None:
        api_url = "None => This IP is in local cache."

    print("{}\n{}\n{}".format(onmagenta("*" * 120), onmagenta("VirusTotal: -> URL:" + api_url), onmagenta("*" * 120)))

    print("{}VirusTotal (https://www.virustotal.com/) inspects items with over 70 antivirus scanners and URL/domain blacklisting services, in addition to a myriad of tools to extract signals from "
          "the studied content.{}".format(Fore.LIGHTWHITE_EX + Style.BRIGHT, Style.RESET_ALL))
    print("{}IP VirusTotal report for: {}{}\n{}".format(Fore.LIGHTGREEN_EX, theip, Style.RESET_ALL, "=" * 120))

    print("\n{}RESUME TABLE:{}".format(Fore.LIGHTYELLOW_EX, Style.RESET_ALL))
    t = PrettyTable(["Key", "Total issues", "Number of positives", "Different dates"])
    t.align = "l"
    if "undetected_downloaded_samples" in data:
        i, j, p = key_virustotal_report(data["undetected_downloaded_samples"])
        t.add_row(["Undetected downloaded samples", i, j, p])
    else:
        t.add_row(["Undetected downloaded samples", 0, 0, 0])

    if "detected_downloaded_samples" in data:
        i, j, p = key_virustotal_report(data["detected_downloaded_samples"])
        t.add_row(["Detected downloaded samples", i, j, p])
    else:
        t.add_row(["Detected downloaded samples", 0, 0, 0])

    if "undetected_referrer_samples" in data:
        i, j, p = key_virustotal_report(data["undetected_referrer_samples"])
        t.add_row(["Undetected referer samples", i, j, p])
    else:
        t.add_row(["Undetected referer samples", 0, 0, 0])

    if "detected_referrer_samples" in data:
        i, j, p = key_virustotal_report(data["detected_referrer_samples"])
        t.add_row(["Detected referer samples", i, j, p])
    else:
        t.add_row(["Detected referer samples", 0, 0, 0])

    if "detected_urls" in data:
        i, j, p = key_virustotal_report(data["detected_urls"])
        t.add_row(["Detected URLs", i, j, p])
    else:
        t.add_row(["Detected URLs", 0, 0, 0])
    print(t)

    if "resolutions" in data:
        print("\n{}Hostnames that this IP address resolves to: {}".format(Fore.LIGHTYELLOW_EX, Style.RESET_ALL))
        ss = ""
        if len(data["resolutions"]) > 0:
            for hosts in data["resolutions"]:
                ss += (hosts["hostname"] + ", ")
            print(ss[:-2])
        else:
            print_error_banner("Not hostnames resolving this IP returned.")

    if "detected_urls" in data:
        print("\n{}URLs at this IP address that have at least 1 detection on a URL scan: {}".format(Fore.LIGHTYELLOW_EX, Style.RESET_ALL))
        ss = ""
        if len(data["detected_urls"]) > 0:
            for urls in data["detected_urls"]:
                ss += (urls["url"] + ", ")
            print(ss[:-2])
        else:
            print_error_banner("Not URLs associated at this IP address returned.")
    print(f"{'▀' * 120}\n\n\n")


def print_virustotal_whois(data, theip):
    print("\n{}VirusTotal inspects items with over 70 antivirus scanners and URL/domain blacklisting services, in addition to a myriad of tools to extract signals from "
          "the studied content.{}".format(Fore.LIGHTWHITE_EX + Style.BRIGHT, Style.RESET_ALL))
    print("{}IP VirusTotal Whois for {}{}\n{}".format(Fore.LIGHTGREEN_EX, theip, Style.RESET_ALL, "=" * 120))
    if "whois" in data:
        print(data["whois"], "\n")
    else:
        print_error_banner("No VirusTotal Whois data information.")


def print_spamhaus(data, theip, reverseip):
    print("{}\n{}\n{}".format(onmagenta("*" * 120), onmagenta("SpamHaus: -> " + reverseip), onmagenta("*" * 120)))
    print("{}The Spamhaus Project is an international nonprofit organization that tracks spam and related cyber threats such as phishing, malware and botnets, provides realtime "
          "actionable and highly accurate threat intelligence to the Internet's major networks, corporations and security vendors.{}".format(Fore.LIGHTWHITE_EX + Style.BRIGHT,
                                                                                                                                             Style.RESET_ALL))
    print("{}IP SpamHaus query DNSBL: {}{}\n{}".format(Fore.LIGHTGREEN_EX, theip, Style.RESET_ALL, "=" * 120))
    if data is None or data["status"] == "0":
        print_error_banner("The DNS query name does not exist: {}".format(reverseip))
    else:
        print('{}ZEN zen.spamhaus.org combines zone:{} {} - {}{}'.format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, data["zen_code"], data["zen_ret_code"], Style.RESET_ALL))
        print('{}          ZEN zen.spamhaus.org CIF:{} {} - {}{}'.format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, data["zen_cif_code"], data["zen_ret_cif_code"], Style.RESET_ALL))
        print('{}                  ZEN Spamhaus URL:{} {}{}'.format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, data["url"], Style.RESET_ALL))
    print(f"{'▀' * 120}\n\n\n")


def util_print_alienvault_endpoint_simple(alerts, cached=False, otx_ip='0.0.0.0'):
    api_url = ""
    if cached:
        api_url = "None => This IP is in local cache."

    print("{}\n{}\n{}".format(onmagenta("*" * 120), onmagenta("AlienVault OTX: -> URL: " + api_url), onmagenta("*" * 120)))
    print("{}AlienVault's OTX (https://otx.alienvault.com/) is a project home for monitoring the status of Open Threat Exchange.".format(Fore.LIGHTWHITE_EX + Style.BRIGHT, Style.RESET_ALL))

    if cached:
        print("{}AlienVault OTX Reports for {} - ({}){}\n{}".format(Fore.LIGHTGREEN_EX, otx_ip, "This IP is in local cache !!", Style.RESET_ALL, "=" * 120))
    else:
        print("{}AlienVault OTX Reports for {}{}\n{}".format(Fore.LIGHTGREEN_EX, otx_ip, Style.RESET_ALL, "=" * 120))

    if len(alerts) > 1:
        print("{}IP Address            :{} {} (IPv4)\t\t{}{}\n".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, otx_ip, Fore.LIGHTRED_EX, alerts[0]))
        print("{}Pulses in wich this IP was present:\n{}".format(Fore.YELLOW, "=" * 60))
        for i in range(1, len(alerts)):
            print("\t{}{:02d} - {}".format(Fore.LIGHTYELLOW_EX, i, alerts[i]))
    else:
        print("{}IP Address            :{} {} (IPv4)\t\t{}{}\n".format(Fore.LIGHTYELLOW_EX, Fore.LIGHTWHITE_EX, otx_ip, Fore.LIGHTGREEN_EX, alerts[0]))
    # print(Style.RESET_ALL + f"{'▀' * 120}\n\n\n")


def util_print_alienvault_endpoint_ext(d_response, cached=False, otx_ip='0.0.0.0'):
    if "general" not in d_response:
        print(onwhite(f"{'▀' * 120}\n\n\n"))
        return
    print(onblack("\n"))
    t = PrettyTable(["ASN", "Country", "Region", "City", "Latitude", "Longitude", "Involved Sections"])
    t._max_width = {"Involved Sections": 40}
    t.align = "l"
    t.add_row([d_response["general"]["asn"], d_response["general"]["country_name"], d_response["general"]["region"], d_response["general"]["city"], d_response["general"]["latitude"],
               d_response["general"]["longitude"], ", ".join(d_response["general"]["sections"])])

    print("{}General information: Geographic + Sections involved:\n{}".format(Fore.YELLOW, "=" * 60))
    print(onyellow(t))
    print(onwhite(f"{'▀' * 120}\n\n\n"))

# END FUNCTIONS FROM REPUTATION
####################################################################


'''
def util_print_alienvault_endpoint_ext(d_response, cached=False, otx_ip='0.0.0.0'):
    sorted_data = collections.OrderedDict(sorted(data.items(), key=lambda kv: kv[1], reverse=True))
    t = PrettyTable(["# Citations", "Category name", "Description"])
    t.align = "l"
    for (key, value) in sorted_data.items():
        wrap_line = wrap(str(abtypes[key][1]) or "", VAL_WRAP_WIDTH_EXT) or [""]
        t.add_row([value, abtypes[key][0], wrap_line[0]])
        for subseq in wrap_line[1:]:
            t.add_row(["", "", subseq])

    if len(sorted_data) > 0:
        print("\n{}IP Abuse Reports for {} -> Involved categories{}\n{}".format(Fore.LIGHTGREEN_EX, otx_ip, Style.RESET_ALL, "=" * 120))
        print(t, "\n")
'''


