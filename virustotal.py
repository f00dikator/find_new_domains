# interact with VT domains endpoint API

import requests
import logging
#import pdb


class VT:
    def __init__(self, apikey=None, verify=True):
        self.checked_domains = []
        self.checked_categories = {}
        if apikey:
            self.apikey = apikey
            self.domains_base_url = 'https://www.virustotal.com/api/v3/domains/'
            self.verify = verify
        else:
            logging.error("NO API Key. Exiting")
            print("NO API Key. Exiting")
            exit(0)

        self.generic_session = requests.Session()
        self.generic_session.verify = verify
        self.generic_session.headers = {"Accept": "*/*",
                                        "x-apikey": "{}".format(self.apikey)}


    def check_domain(self, search_item, just_classification=False):
        if search_item in self.checked_domains:
            return self.checked_categories[search_item]
        else:
            self.checked_domains.append(search_item)

        uri = "{}{}".format(self.domains_base_url, search_item)
        try:
            ret = self.generic_session.get(uri)
            if ret.status_code == 200:
                classifications = self.get_classification(ret.json())
                self.checked_categories[search_item] = classifications
                if just_classification:
                    return classifications
                else:
                    return ret.json()
            else:
                logging.error("Return status code other than 200 : {} for domain {}".format(ret.status_code, search_item))
        except Exception as e:
            logging.error("Failed to execute search for {}. Error: {}".format(search_item, e))

        return None

    def get_classification(self, my_record):
        cats = []
        if my_record:
            try:
                for record in my_record['data']['attributes']['categories']:
                    rec_type = my_record['data']['attributes']['categories'][record]
                    if rec_type not in cats:
                        cats.append(rec_type)
            except Exception as e:
                logging.error("Failed to extract categories from record. Returning empty list. Error: {}".format(e))
                return cats

        return cats
