# -*- coding: utf-8 -*-
# This script is Copyright (C) John Lampe
# Version: 1.0
# Author : John Lampe

import requests
import json
import pdb
import logging

class whois_client:
    def __init__(self, verify=False):
        self.base_url = "https://api.domaintools.com/v1/domaintools.com/whois/"
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers = {"Content-Type": "application/json", "Accept": "application/json"}


    def get(self, domain, **kwargs):
        if not domain:
            logging.error('No domain provided for GET Request')
            return []

        try:
            request_url = "{}/{}".format(self.base_url, domain)
            get_params = kwargs.get('params')
            if get_params:
                logging.info("Issuing GET {} with params set to {}".format(request_url,get_params)) 
                http_response = self.session.get(request_url,
                                                 params=get_params)
            else:
                http_response = self.session.get(request_url, **kwargs)
                logging.info("Issuing GET {}".format(request_url))

            if http_response and http_response.json():
                return http_response.json()
            else:
                logging.error("Nothing returned for request {}".format(request_url))
                try:
                    logging.error("Error message {}".format(http_response.json()))
                except:
                    logging.error("No error message was returned")

                return []
        except Exception as e:
            logging.error("Failed to send GET request {} : {}".format(request_url, e))






