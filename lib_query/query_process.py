#!/usr/bin/env python3


################################################################################
# A multiprocess instance that is responsible for querying the pwnedpasswords
# API and coordinating with the main parent process as to which hash to query
#
################################################################################


# Global imports
import sys
import queue
import time

# Local imports
from .pwned_passwords_api import get_list_for_hash
    
    
## Main loop for the query process. This is what is called when it is created
#
# Variables:
#
#   url: The base URL to query for the pwned passwords service
#   ptoc_queue: The parent to child queue
#   ctop_queue: The child to parent queue
#
def launch_query_process(url, ptoc_queue, ctop_queue):

    print("Launching query process",file=sys.stderr)
    
    hash_prefix = None
    
    while True:
        # Query the queue to see if there is a new hash to use
        # Note: if queue is empty will throw an exception
        try:
            command = ptoc_queue.get_nowait()
            if command['action'] == 'query':
                hash_prefix = command['prefix']
                
            # If it is not a query, exit
            else:
                break
                
        except queue.Empty:
            pass
        
        # Query the pwned passwords service
        if hash_prefix != None:
        
            try:
                status_code, content = get_list_for_hash('https://api.pwnedpasswords.com/', 'range/', hash_prefix)
            except:
                continue
            
            # If an error status code appears
            if str(status_code) != "200":
                # Let the main process know
                ctop_queue.put({'prefix':hash_prefix, 'status':str(status_code)})
                print("Prefix: " + str(hash_prefix) + " : " + str(status_code))
                # Sleep for a second in case rate limiting is occuring
                time.sleep(1)
            
            # Used for debugging
            #result = str(hash_prefix + '\t' + str(status_code) + "\t" + str(len(content)))
            #print(result)
    return
    