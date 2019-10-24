#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Get-OTX-IOCs
# Retrieves IOCs from Open Threat Exchange
#
# Create an account and select your feeds
# https://otx.alienvault.com
#
# Changes:
# 16.12.2017 - Merged the changes by Scott with the code base
# 22.11.2017 - Scott Carpenter uberbigun@gmail.com
# 13.02.2018 - Reworked the hash whitelist
# 13.08.2018 - iChina
#

from OTXv2 import OTXv2
import re
import os
import sys
import json
import time
import traceback
import argparse

OTX_KEY = '44ef825a3045710a509ac367cfc76fc8bc56ba9d8896c952e7805366145d37e9'

# Hashes that are often included in pulses but are false positives
HASH_WHITELIST = ['e617348b8947f28e2a280dd93c75a6ad',
                  '125da188e26bd119ce8cad7eeb1fc2dfa147ad47',
                  '06f7826c2862d184a49e3672c0aa6097b11e7771a4bf613ec37941236c1a8e20',
                  'd378bffb70923139d6a4f546864aa61c',
                  '8094af5ee310714caebccaeee7769ffb08048503ba478b879edfef5f1a24fefe',
                  '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
                  'b6f9aa44c5f0565b5deb761b1926e9b6',
                  'b1442e85b03bdcaf66dc58c7abb98745dd2687d86350be9a298a1d9382ac849b',
                  'a11a2f0cfe6d0b4c50945989db6360cd',
                  # Empty file
                  'd41d8cd98f00b204e9800998ecf8427e',
                  'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                  # One byte line break file (Unix) 0x0a
                  '68b329da9893e34099c7d8ad5cb9c940',
                  'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc',
                  '01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b',
                  # One byte line break file (Windows) 0x0d0a
                  '81051bcc2cf1bedf378224b0a93e2877',
                  'ba8ab5a0280b953aa97435ff8946cbcbb2755a27',
                  '7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6',
                  # File filled with 99 zeros (probably caused by AV)
                  'fa8715078d45101200a6e2bf7321aa04',
                  'd991c16949bd5e85e768385440e18d493ce3aa46',
                  '4b298058e1d5fd3f2fa20ead21773912a5dc38da3c0da0bbc7de1adfb6011f1c',
                  '620f0b67a91f7f74151bc5be745b7110',
                  '1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d',
                  'ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7',
                  ]
FILENAMES_WHITELIST = ['wncry']
DOMAIN_WHITELIST = ['proofpoint.com']


class WhiteListedIOC(Exception): pass


class OTXReceiver():
    # IOC Strings
    hash_iocs = ""
    filename_iocs = ""
    c2_iocs_ipv4 = ""
    c2_iocs_ipv6 = ""
    c2_iocs_domain = ""

    # Output format
    separator = ";"
    use_csv_header = False
    #use_csv_header = True
    #extension = "csv"
    extension = "txt"
    hash_upper = True
    filename_regex_out = True

    def __init__(self, api_key, siem_mode, debug, proxy, csvheader, extension):
        self.debug = debug
        self.otx = OTXv2(api_key, proxy)

        if siem_mode:
            self.separator = ","
            self.use_csv_header = csvheader
            self.extension = extension
            self.hash_upper = True
            self.filename_regex_out = False

    def get_iocs_last(self):
        # mtime = (datetime.now() - timedelta(days=days_to_load)).isoformat()
        print("Starting OTX feed download ...")
        self.events = self.otx.getall()
        print("Download complete - %s events received" % len(self.events))
        # json_normalize(self.events)
        # print(self.events)
		
    def write_APT_iocs(self, ioc_folder):
        reload(sys)
        sys.setdefaultencoding("utf-8")
        hash_ioc_file = os.path.join(ioc_folder, "otx-hash-iocs.{0}".format(self.extension))
        filename_ioc_file = os.path.join(ioc_folder, "otx-filename-iocs.{0}".format(self.extension))
        c2_ioc_ipv4_file = os.path.join(ioc_folder, "otx-c2-iocs-ipv4.{0}".format(self.extension))
        c2_ioc_ipv6_file = os.path.join(ioc_folder, "otx-c2-iocs-ipv6.{0}".format(self.extension))
        c2_ioc_domain_file = os.path.join(ioc_folder, "otx-c2-iocs.{0}".format(self.extension))
        APT = os.path.join(ioc_folder, "APT.txt")
        try:
            APT_fh = open(APT, "w+") 
        except:
            print("open file error!")
        print("Processing indicators APT...")
        #APT
        APT = 10000000
        for event in self.events:
            #name&country
            details = []
            countries = []
            if event["adversary"] != None:
                name = '"' + event["adversary"] + '"'
            else:
                name = '""'
	    #标题
            if event["name"] != None:
                BT = '"' + event["name"] + '"'
            else:
                BT = '""'
            ##only_id
            if event["id"] != None:
                id = '"' + event["id"] + '"'
            else:
                id = '""'
            target_countries = event["targeted_countries"]
            for target_country in target_countries:
                countries.append(target_country)
            if countries != None:
                country = '"' + ','.join(countries) + '"'
            for reference in event["references"]:
                reference = '"' + reference + '"'
                details.append(reference)
            if details != None:
                detail = '[' + ','.join(details) + ']'
            else:
                detail = '[]'
            dt = event["created"]
            dt = dt[:19].replace('T',' ')
            dt = time.strptime(dt,"%Y-%m-%d %H:%M:%S")
            etime = str(int(time.mktime(dt)))
            hashs = []
            domains = []
            ip = []
            try:
                for indicator in event["indicators"]:
                    #collection = []
                    
                    try:
                        # Description

                        # Hash IOCs
                        if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'):

                            # Whitelisting
                            if indicator["indicator"].lower() in HASH_WHITELIST:
                                raise WhiteListedIOC
                            #hash = indicator["indicator"]
                            #hashs = hashs + indicator["indicator"] + ','
                            else:
                                hash_temp = '"' + indicator["indicator"].lower() + '"'
                                if (len(hash_temp)==34):
									hashs.append(hash_temp)
                                else:
									continue
                        if indicator["type"] in ('domain', 'hostname', 'CIDR'):
                            #domains = domains + indicator["indicator"] + ',' 
                            domain_temp = '"' + indicator["indicator"] + '"'
                            domains.append(domain_temp)
                        if indicator["type"] in ('IPv4'):
                            ip_temp = '"' + indicator["indicator"] + '"'
                            ip.append(ip_temp)
                    except WhiteListedIOC as e:
                        pass     
            except Exception as e:
                traceback.print_exc()
            if hashs != None:
                hash = '[' + ','.join(hashs) + ']'
            else:
                hash = '[]'
            if domains != None:
                domain = '[' + ','.join(domains) + ']'
            else:
                domain = '[]'
            if ip != None:
                iptable = '[' + ','.join(ip) + ']'
            else:
                iptable = '[]'
            #判断name长度是否大于3，如果大于3判断为有组织
            if (len(name)>=3):
                APT += 1
                sid = APT
                s = r'{"name":' + name + r',"country":' + country + r', "hash":' + hash + r', "domain": ' + domain + r',"ip":' + iptable + r',"detail":' + detail + r', "etime":' + etime + r', "sid":' + str(sid) + r',"yid":' + str(id) + r'}'
            else:
                continue
            #s = json.dumps(s)
            APT_fh.write(s + '\n')                
        APT_fh.close()
		
    def write_BLACK_iocs(self, ioc_folder):
        reload(sys)
        sys.setdefaultencoding("utf-8")
        hash_ioc_file = os.path.join(ioc_folder, "otx-hash-iocs.{0}".format(self.extension))
        filename_ioc_file = os.path.join(ioc_folder, "otx-filename-iocs.{0}".format(self.extension))
        c2_ioc_ipv4_file = os.path.join(ioc_folder, "otx-c2-iocs-ipv4.{0}".format(self.extension))
        c2_ioc_ipv6_file = os.path.join(ioc_folder, "otx-c2-iocs-ipv6.{0}".format(self.extension))
        c2_ioc_domain_file = os.path.join(ioc_folder, "otx-c2-iocs.{0}".format(self.extension))
        BLACK = os.path.join(ioc_folder, "BLACK.txt")
        try:
            BLACK_fh = open(BLACK, "w+") 
        except:
            print("open file error!")
        print("Processing indicators BLACK...")
        #BLACK
        BLACK = 50000000
        for event in self.events:
            #name&country
            details = []
            countries = []
            if event["adversary"] != None:
                name = '"' + event["adversary"] + '"'
            else:
                name = '""'
	    #标题
            if event["name"] != None:
                BT = '"' + event["name"] + '"'
            else:
                BT = '""'
            ##only_id
            if event["id"] != None:
                id = '"' + event["id"] + '"'
            else:
                id = '""'
            target_countries = event["targeted_countries"]
            for target_country in target_countries:
                countries.append(target_country)
            if countries != None:
                country = '"' + ','.join(countries) + '"'
            for reference in event["references"]:
                reference = '"' + reference + '"'
                details.append(reference)
            if details != None:
                detail = '[' + ','.join(details) + ']'
            else:
                detail = '[]'
            dt = event["created"]
            dt = dt[:19].replace('T',' ')
            dt = time.strptime(dt,"%Y-%m-%d %H:%M:%S")
            etime = str(int(time.mktime(dt)))
            hashs = []
            domains = []
            ip = []
            try:
                for indicator in event["indicators"]:
                    #collection = []
                    
                    try:
                        # Description

                        # Hash IOCs
                        if indicator["type"] in ('FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256'):

                            # Whitelisting
                            if indicator["indicator"].lower() in HASH_WHITELIST:
                                raise WhiteListedIOC
                            #hash = indicator["indicator"]
                            #hashs = hashs + indicator["indicator"] + ','
                            else:
                                hash_temp = '"' + indicator["indicator"].lower() + '"'
                                if (len(hash_temp)==34):
									hashs.append(hash_temp)
                                else:
									continue
                        if indicator["type"] in ('domain', 'hostname', 'CIDR'):
                            #domains = domains + indicator["indicator"] + ',' 
                            domain_temp = '"' + indicator["indicator"] + '"'
                            domains.append(domain_temp)
                        if indicator["type"] in ('IPv4'):
                            ip_temp = '"' + indicator["indicator"] + '"'
                            ip.append(ip_temp)
                    except WhiteListedIOC as e:
                        pass     
            except Exception as e:
                traceback.print_exc()
            if hashs != None:
                hash = '[' + ','.join(hashs) + ']'
            else:
                hash = '[]'
            if domains != None:
                domain = '[' + ','.join(domains) + ']'
            else:
                domain = '[]'
            if ip != None:
                iptable = '[' + ','.join(ip) + ']'
            else:
                iptable = '[]'
            #判断name长度是否大于3，如果大于3判断为有组织
            if (len(name)>=3):
                continue
            else:
                BLACK += 1
                sid = BLACK
                s = r'{"name":' + str(BT) + r',"country":' + country + r', "hash":' + hash + r', "domain": ' + domain + r',"ip":' + iptable + r',"detail":' + detail + r', "etime":' + etime + r', "sid":' + str(sid) + r',"yid":' + str(id) + r'}'
            #s = json.dumps(s)
            BLACK_fh.write(s + '\n')                
        BLACK_fh.close()
        


def my_escape(string):
    return re.sub(r'([\-\(\)\.\[\]\{\}\\\+])', r'\\\1', string)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='OTX IOC Receiver')
    parser.add_argument('-k', help='OTX API key', metavar='APIKEY', default=OTX_KEY)
    # parser.add_argument('-l', help='Time frame in days (default=1)', default=1)
    parser.add_argument('-o', metavar='dir', help='Output directory', default='../../iocs')
    parser.add_argument('-p', metavar='proxy', help='Proxy server (e.g. http://proxy:8080 or '
                                                    'http://user:pass@proxy:8080', default=None)
    parser.add_argument('--verifycert', action='store_true', help='Verify the server certificate', default=False)
    parser.add_argument('--siem', action='store_true', default=False,
                        help='CSV output for use in SIEM systems (e.g. Splunk)')
    parser.add_argument('--nocsvheader', action='store_true', default=False,
                        help='Disable header in CSV output (e.g. McAfee SIEM)')
    parser.add_argument('-e', metavar='ext', help='File extension', default='txt')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()

    if len(args.k) != 64:
        print("Set an API key in script or via -k APIKEY. Go to https://otx.alienvault.com create an account and get your own API key")
        sys.exit(0)

    # Create a receiver
    otx_receiver = OTXReceiver(api_key=args.k, siem_mode=args.siem, debug=args.debug, proxy=args.p,
                               csvheader=(not args.nocsvheader), extension=args.e)

    # Retrieve the events and store the IOCs
    # otx_receiver.get_iocs_last(int(args.l))
    otx_receiver.get_iocs_last()

    # Write IOC files
    otx_receiver.write_APT_iocs(ioc_folder=args.o)
    otx_receiver.write_BLACK_iocs(ioc_folder=args.o)
