#!/usr/bin/env python3


################################################################################
# Contains logic to retrieve a response from the pwned passwords API given
# a target hash
#
################################################################################


import sys
import requests
    
    
## Retrieves a response from pwned passwordsfor a given hash prefix.
#
# Variables:
#
#   url: The base URL to query for pwned passwords
#
#   hash_prefix: The hash prefix to look update
#
def get_list_for_hash(url, hash_prefix):

    r = requests.get(url + hash_prefix, stream=True)
        
    return r.status_code, r.content