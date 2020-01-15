#!/usr/bin/env python3


################################################################################
# Contains logic to retrieve a response from the pwned passwords API given
# a target hash
#
################################################################################


import sys
import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl


## This allows custom modification of TLS parameters
#
# Currently forcing TLS version 1.2
#
class MyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                   maxsize=maxsize,
                                   block=block,
                                   ssl_version=ssl.PROTOCOL_TLSv1_2)

    
## Retrieves a response from pwned passwordsfor a given hash prefix.
#
# Variables:
#
#   url: The base URL to query for pwned passwords
#
#   query: The query string to use after the URL
#
#   hash_prefix: The hash prefix to look update
#
def get_list_for_hash(url, query, hash_prefix):

    s = requests.Session()
    s.mount('https://', MyAdapter())

    try:
        r = s.get(url + query + hash_prefix, stream=True)
    except:
        return "NO_CONNECTION", None
        
    return r.status_code, r.content
    
    
    
## Retreives the IP address currently assocated with a URL.
#
# Note: The ip mapping can change reguarly, so these results are good in general
#       but can fail when using it elsewhere
#
def dns_lookup(url):
    return socket.gethostbyname(url)