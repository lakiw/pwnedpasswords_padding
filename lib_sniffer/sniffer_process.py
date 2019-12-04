#!/usr/bin/env python3


################################################################################
# A multiprocess instance that is responsible for sniffing https encrypted
# traffic to pwnedpasswords and recording the size of each session
#
################################################################################


# Global imports
import sys
import queue
import time

# Local imports
from .pyshark_functions import sniff_pwnedpasswords_sessions    
    
## Main loop for the sniffer process. This is what is called when it is created
#
# Variables:
#   interval_time: The starting interval to sniff sessions for
#                  Note: I may evenually adjust this on the fly to optimize it
#   num_samples: The minimun number of samples to collect for each
#                hash prefix
#   ptoc_queue: The parent to child queue
#   ctop_queue: The child to parent queue
#
# Command Format
#
#   {
#       'action':['scan','stop'],
#   }
#
def launch_sniffer_process(interval_time, num_samples, interface, ptoc_queue, ctop_queue):

    print("Launching sniffer process",file=sys.stderr)
    
    while True:
        # Query the queue to see if a new sniffing session should begin
        # Note: Using a blocking get since it shouldn't be working without
        #       a command
        try:
            command = ptoc_queue.get()
        except queue.Empty:
            # shoudln't hit this, but if we do skip to the next round
            continue
        
        # Run a scan to collect samples of pp sessions
        if command['action'] == 'scan' : 
            saved_sessions = []
            
            # Keep trying to collect samples untill it has collected the minimum
            # amount
            while len(saved_sessions) < num_samples :
                saved_sessions.extend(sniff_pwnedpasswords_sessions(time = interval_time, interface = interface))
             
            ctop_queue.put(saved_sessions)
        # End the sniffing sessions and exit        
        elif command['action'] == 'stop' :
            break
        else:
            print("Invalid command sent to scanner",file=sys.stderr)
          
        
    return
    