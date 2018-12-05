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

def main():
    print("Sniffing ...")
    sniff(iface = interface, filter = "port 53", prn = querysniff, store = 0)

    exit(0)


def querysniff(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
            domain_to_be_resolved = pkt.getlayer(DNS).qd.qname.decode("utf-8")
            names = domain_to_be_resolved.split('.')
            if len(names) >= 3:
                root = "{}.{}".format(names[len(names)-3], names[len(names)-2])
                if root not in DOMAINS:
                    print("{} -> {} checking whois info for {}".format(ip_src, ip_dst, root))
                    logging.info("{} -> {} checking whois info for {}".format(ip_src, ip_dst, root))
                    DOMAINS.append(root)
                    if gather_info(root):
                        print ("DOMAIN {} was recently created".format(root))
                        logging.info("DOMAIN {} was recently created".format(root))



def gather_info(domain):
    newly_created = 24 * 3600 * 14	#2 weeks
    creation_date = ""
    http_response = myclient.get(domain=domain)
    record = http_response['response']['whois']['record']
    creation_regex = re.compile(r'Creation Date: ([0-9]{4}-[0-9]{2}-[0-9]{2}).([0-9]{2}:[0-9]{2}:[0-9]{2})')

    result = re.search(creation_regex, record, flags=0)
    if result:
        creation_date = "{} {}".format(result.group(1), result.group(2))
    else:
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
 


def convert_date_to_epoch(datestr):
    #2018-05-20 18:50:02
    date_regex = re.compile(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})[ ]+([0-9]{2}):([0-9]{2}):([0-9]{2})$')
    result = re.search(date_regex, datestr, flags=0)
    if result:
        ret = datetime.datetime(int(result.group(1)),
                  int(result.group(2)), int(result.group(3)),
                  int(result.group(4)), int(result.group(5)),
                  int(result.group(6))).strftime('%s')
    else:
        ret = None
        logging.error("Invalid date/time passed to input - {}".format(datestr))

    return ret




def configure_logging(conf, script_name):
    """
    Takes in the logging section of the configuration file and creates a basic logger


    :param conf: Logging Configuration Dictionary
    :param script_name: Name of the script being executed
    :return:
    """
    import urllib3
    urllib3.disable_warnings()

    log_file = os.path.join(conf['path'], '{0}.log'.format(script_name.split('.')[0]))
    logging.basicConfig(filename=log_file,
                        level=conf['log_level'],
                        format=conf['log_format'],
                        datefmt=conf['date_format'],
                        filemode='w')
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Whois info gathering')
    parser.add_argument('-c', action='store', dest='config_path', help='config file')
    parser.add_argument('-i', action='store', dest='interface', help='Interface to monitor')

    args = parser.parse_args()

    if args.config_path is None:
        raise RuntimeError('No configuration file provided. Exiting...')

    if not os.path.isfile(args.config_path):
        raise RuntimeError('Configuration file provided does not exist')

    with open(args.config_path) as c:
        config = yaml.load(c)

    configure_logging(config['logging'], __file__)
    logging.info('Executing Script: {0}'.format(__file__))

    if args.interface:
        interface = args.interface
    else:
        logging.error("No interface passed. Exiting")
        exit(0)

    # global 
    DOMAINS = []
    myclient = whois_query.whois_client()

    main()

