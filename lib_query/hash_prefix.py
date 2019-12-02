#!/usr/bin/env python3


################################################################################
# Generates hash prefixes and allows incrementing them
#
################################################################################


import sys


## A hash prefix
#
class HashPrefix:

    ## Initialization function
    #
    def __init__(self, initial = '00000', length = 5):
        
        # Sanity check to make sure the initial value is of the correct length
        if len(initial) != length:
            print("Error, inital value and length of hash prefix do not match", file=sys.stderr)
            raise Exception
            
        self.value = int(initial, base=16)
        self.length = length
        
    
    ## Increments the hash by 1
    #
    # Return Value:
    #
    # 0: If everything went ok
    # 1: If an overflow for the given length occured
    #
    def increment(self):
    
        self.value += 1
        
        # Check for overflow by converting to a string 
        #
        # Note: adding +2 to length to ignore the '0x' at the front
        if len(hex(self.value)) > self.length + 2:
            return 1
        
        return 0
        
        
    ## Returns the hash prefix value as a string of length N
    #
    # Return Value:
    #
    # value: A string representation of the hash prefix
    #
    def get_value(self):
        ret_value = hex(self.value) 
        return ret_value[2:].zfill(self.length)
