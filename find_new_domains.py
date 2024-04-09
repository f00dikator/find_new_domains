# -*- coding: utf-8 -*-
# Version: 1.0.0

__author__ = 'John Lampe'
__email__ = 'dmitry.chan@gmail.com'

import base64
import yaml
import logging
import os
import argparse
import string
import requests
import json
import whois_query
import pdb
import re
import time
from scapy.all import *
import sys
import calendar
import datetime
#import commands
import subprocess
from logging.handlers import TimedRotatingFileHandler
import syslog


def main():
    print("Sniffing ...")
    sniff(iface = interface, filter = "port 53", prn = querysniff, store = 0)

    exit(0)


def check_for_malware(domain):
    ret = False

    if not malware_file:
        return ret

    try:
        if malware_domains[domain] == 1:
            return True
        else:
            return False
    except:
        return False

    return ret



def querysniff(pkt):
     esni_regex = r"_esni\."
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            levels_to_flag_on = ['critical', 'high'] 
            domain_to_be_resolved = pkt.getlayer(DNS).qd.qname.decode("utf-8")
            domain_to_be_resolved = domain_to_be_resolved[:-1]
            if domain_to_be_resolved not in FQDNS:
                is_malware = check_for_malware(domain_to_be_resolved)
            else:
                is_malware = False
                
            match = re.search(esni_regex, domain_to_be_resolved, re.IGNORECASE)
            if match != None:
                logging.info("WARNING! {} is using Encrypted SNI (ESNI). Investigate".format(domain_to_be_resolved))
                syslog.syslog("WARNING! {} is using Encrypted SNI (ESNI). Investigate".format(domain_to_be_resolved))


            if is_malware:
                logging.info("WARNING! {} is part of a blacklist malware list. Investigate".format(domain_to_be_resolved))
                syslog.syslog("WARNING! {} is part of a blacklist malware list. Investigate".format(domain_to_be_resolved))
                FQDNS.append(domain_to_be_resolved)
            else:
                if domain_to_be_resolved not in FQDNS:
                    FQDNS.append(domain_to_be_resolved)
                    if pulsedive_key:
                        data = {'indicator': "{}".format(domain_to_be_resolved), 'pretty':'1', 'key': pulsedive_key}
                        try:
                            req = requests.post('https://pulsedive.com/api/info.php', data=data).json()
                            risk = req['risk']
                        except:
                            logging.info("No pulsedive info for {}".format(domain_to_be_resolved))
                            risk = None
                    else:
                        risk = None
                else:
                    risk = None

                if risk in levels_to_flag_on:
                    logging.info("Warning! {} pulsedive threat intel rated as a {}".format(domain_to_be_resolved, risk))
                    syslog.syslog("Warning! {} pulsedive threat intel rated as a {}".format(domain_to_be_resolved, risk))

            names = domain_to_be_resolved.split('.')
            if len(names) >= 2:
                root = "{}.{}".format(names[len(names)-2], names[len(names)-1])
                if root not in DOMAINS:
                    print("{} -> {} checking whois info for {}".format(ip_src, ip_dst, root))
                    logging.info("{} -> {} checking whois info for {}".format(ip_src, ip_dst, root))
                    DOMAINS.append(root)
                    if gather_info(root):
                        print ("DOMAIN {} was recently created".format(root))
                        logging.info("WARNING! DOMAIN {} was recently created".format(root))
                        syslog.syslog("WARNING! DOMAIN {} was recently created".format(root))



def gather_info(domain):
    newly_created = 24 * 3600 * 14	#2 weeks
    creation_date = [] 
    #record = commands.getoutput("whois {}".format(domain))
    record = subprocess.run(["/usr/bin/whois", " {}".format(domain)], capture_output=True).stdout.decode()
    #                             Creation Date: 1997-09-15T04:00:00Z
    #                             created:      1990-11-28
    creation_regex = re.compile(r'Creation Date: ([0-9]{4})-([0-9]{2})-([0-9]{2}).([0-9]{2}):([0-9]{2}):([0-9]{2})')
    creation_regex_two = re.compile(r'created: ([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})')

    result = re.search(creation_regex, record, flags=0)
    result2 = re.search(creation_regex_two, record, flags=0)
    if result:
        creation_date = [ int(result.group(i))
                          for i in range (1,7)
                        ]
    elif result2:
        creation_date = [ int(result.group(1)), int(result.group(2)), int(result.group(3)), 0, 0, 0 ]
    else:
        print("No creation date info for domain {}".format(domain))
        logging.error("No creation date info for domain {}".format(domain))

    try:
        epoch_time = float(convert_date_to_epoch(creation_date))
    except:
        epoch_time = False
    
    current_time = time.time()

    if epoch_time and current_time and (current_time - epoch_time) < newly_created:
        return True
    else:
        return False
 


def convert_date_to_epoch(result):
    if result:
        ret = datetime.datetime(result[0], result[1], result[2], result[3], result[4], result[5]).strftime('%s')
    else:
        ret = None
        logging.error("Invalid date/time passed to input - {}".format(datestr))

    return ret




def configure_logging(log_path, date_format, log_format,
                      log_file_name, retention, log_level='INFO'):
    """
    Configures logging based on the pathing, log level, and formatting provided
    :param retention: Number of days to retain the log
    :param log_file_name: Name of the log file
    :param log_path: Path where the log file will be written
    :param date_format: Format the date will appear as in the log file
    :param log_format: Format the entire log message will appear as in the log
    file
    :param log_level: INFO by default, DEBUG if -v argument is given during
    execution
    :return:
    """

    log_file = os.path.join(log_path, log_file_name)

    if not os.path.isdir(log_path):
        os.mkdir("{}".format(log_path))

    rotate_handler = TimedRotatingFileHandler(filename=log_file,
                                              when='midnight',
                                              interval=1,
                                              backupCount=retention)
    # Will be appended to the rotated log: 20190525
    rotate_suffix = "%Y%m%d"
    rotate_handler.suffix = rotate_suffix

    # Attach formatter
    rotate_handler.setFormatter(logging.Formatter(fmt=log_format,
                                                  datefmt=date_format))

    # noinspection PyArgumentList
    logging.basicConfig(handlers=[rotate_handler],
                        level=log_level)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return



def load_malware(malware_file):
    ret = {}
    try:
        with open(malware_file, "r") as fd:
            for line in fd:
                domain = line.strip()
                if len(domain) > 3:
                    ret[domain] = 1    
        logging.info("Loaded {}".format(malware_file))
    except:
        print("Failed to load {}".format(malware_file))

    return ret



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Whois info gathering')
    parser.add_argument('-c', action='store', dest='config_path', help='config file', required=True)
    parser.add_argument('-i', action='store', dest='interface', help='Interface to monitor', required=True)
    parser.add_argument('-f', action='store', dest='malware', help='text file containing malware domains')
    parser.add_argument('-v', action='store_true', dest='verbosity', help='set script verbosity')
    args = parser.parse_args()

    if not os.path.isfile(args.config_path):
        raise RuntimeError('Configuration file provided does not exist')

    with open(args.config_path) as c:
        config = yaml.load(c)

    logging_conf = config['logging']
    if args.verbosity:
        level = logging.DEBUG
    else:
        level = logging.INFO

    configure_logging(log_path=logging_conf['path'],
                      date_format=logging_conf['date_format'],
                      log_format=logging_conf['log_format'],
                      log_file_name='find_new_domains.log',
                      log_level=level,
                      retention=logging_conf['retention'])


    logging.info('Executing Script: {0}'.format(__file__))

    interface = args.interface

    try:
        malware_file = args.malware
        malware_domains = load_malware(malware_file)
    except:
        malware_file = None

    # global 
    DOMAINS = []
    FQDNS = []
    myclient = whois_query.whois_client()
    try:
        pulsedive_key = config['pulsedive']['key']
    except:
        pulsedive_key = None
    main()

