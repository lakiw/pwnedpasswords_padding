#!/usr/bin/env python3


################################################################################
# Responsible for sniffing https encrypted traffic to pwnedpasswords and 
# recording the size of each session
#
################################################################################


# Global imports
import sys
import time

# Local imports
from .pyshark_functions import sniff_pwnedpasswords_sessions, init_capture    
    
    
## Putting functionality for the sniffer to train a PP hash prefix predictore
#  into a function to make adding functionality easier in the future
#
class TrainingSniffer:

    ## Initialization Function
    #
    # Variables:
    #   interval_time: The starting interval to sniff sessions for
    #                  Note: I may evenually adjust this on the fly to optimize it
    #   num_samples: The minimun number of samples to collect for each
    #                hash prefix
    #
    def __init__(self, interval_time, num_samples, interface = None):

        self.interval_time = interval_time
        self.num_samples = num_samples
        self.interface = interface
        self.capture = init_capture(self.interface)
    
    
    ## Sniff the network interface and collect statistics on the pp sessions
    #
    def start_training(self):

        saved_sessions = []
        
        # Keep trying to collect samples untill it has collected the minimum
        # amount
        while len(saved_sessions) < self.num_samples :
            try:
                saved_sessions.extend(sniff_pwnedpasswords_sessions(time = self.interval_time, interface = self.interface, capture = self.capture))
            except:
                continue
         
        return self._format_results(saved_sessions)
        
        
    ## Formatting for returning data to the training program
    #
    def _format_results(self, saved_sessions):
        
        results = {}
        
        for item in saved_sessions:
            if item[1] not in results:
                results[item[1]] = {}
                results[item[1]][item[0]] = 1
            
            elif item[0] not in results[item[1]]:
                results[item[1]][item[0]] = 1
            
            else:
                results[item[1]][item[0]] += 1
                
        return results
    