#!/usr/bin/env python3


########################################################################################
#
# Name: Sniffs pwned passwords lookup sessions and attempts to guess what
#       hash prefix was submitted by the client
#
#  Written by Matt Weir
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#
#  Contact Info: cweir@vt.edu
#
#  sniffer.py
#
#########################################################################################


# Including this to print error message if python < 3.0 is used
from __future__ import print_function
import sys
# Check for python3 and error out if not
if sys.version_info[0] < 3:
    print("This program requires Python 3.x", file=sys.stderr)
    sys.exit(1)

# Global imports    
import argparse
import time
from multiprocessing import Process, Queue
import json

# Local imports
from lib_sniffer.training_sniffer import TrainingSniffer


## Parses the command line
#
# Responsible for parsing the command line.
#
# If you have any command line options that you want to add, they go here.
#
# All results are returned as a dictionary in 'program_info'
#
# If successful, returns True, returns False if value error, program exits if
# argparse catches a problem.
#
def parse_command_line(program_info):

    # Keeping the title text to be generic to make re-using code easier
    parser = argparse.ArgumentParser(
        description= program_info['name'] +
        ', version: ' + 
        program_info['version'],
        formatter_class = argparse.RawTextHelpFormatter
    )
    
    # training file to use
    parser.add_argument(
        '--filename',
        '-f',
        help = 'The training file to use to classify pwned password lookups', 
        metavar = 'FILE_NAME',
        required = True,
        default = program_info['filename']
    )
    
    # The default time chunks the sniffer should sniff for
    parser.add_argument(
        '--time_interval',
        '-t',
        help = 'The default time interval (seconds) the sniffer should run for (sniffer is not multiprocessed so needs to sniff, then parse). Default is ' +str(program_info['time_interval']), 
        metavar = 'SECONDS',
        required = False,
        default = program_info['time_interval']
    )
       
    # The interface to sniff on
    parser.add_argument(
        '--interface',
        '-i',
        help = 'The network interface to sniff on. Default will sniff on all interfaces', 
        metavar = 'INTERFACE_ID',
        required = False,
        default = program_info['interface']
    )
      
    # Parse all the args and save them    
    args=parser.parse_args() 
    
    program_info['filename'] = args.filename
    program_info['time_interval'] = args.time_interval
    program_info['interface'] = args.interface

    return True 
    
  
## Loads a training session from disk
#
def load_training_file(filename):
    
    hash_stats = {}

    with open(filename, 'r') as training_file:
    
        # My apologies for this horrible parsing of a json file --Matt
        for line in training_file:
            data = json.loads(line)          
            for key in data:
                for num_packets in data[key]:
                    if int(num_packets) not in hash_stats:
                        hash_stats[int(num_packets)] = {}
                    
                    for size in data[key][num_packets]:
                        if int(size) not in hash_stats[int(num_packets)]:
                            hash_stats[int(num_packets)][int(size)] = {}
                        if key not in hash_stats[int(num_packets)][int(size)]:
                            hash_stats[int(num_packets)][int(size)][key] = data[key][num_packets][size]
                        else:
                            hash_stats[int(num_packets)][int(size)][key] += data[key][num_packets][size]
            
    return hash_stats        
    
  
## Attempts to identify pwned password hash prefixes
#
def process_results(hash_stats, results):
    
    # The total sessions that were sniffed:
    total_sniffed = 0
    
    # The total sessions that were categorized:
    total_categorized = 0
    
    guessed_prefixes = []
    
    # Loop through all of the results
    for num_packets in results:
        for size in results[num_packets]:
            count = results[num_packets][size]
            total_sniffed += count
            
            # Perform the lookup:
            if num_packets in hash_stats:
                if size in hash_stats[num_packets]:
                
                    # Found a potential match
                    total_categorized += count
                    guessed_prefixes.append({'num_packets':num_packets,'size':size, 'count':count})
                    
        
    # Print top level results
    print("Number of PwnedPasswords Lookups Parsed: " + str(total_sniffed))
    print("Number of Lookups Categorized:           " + str(total_categorized))
    print("Guesses-------------------------------")
    
    for item in guessed_prefixes:
        print("TLS Session Size: " + str(item['size']))
        print("Num Sessions:" +  str(item['count']))
        print("\tHash Prefixes:")
        print("\t------------------")
        for hash_prefix in hash_stats[item['num_packets']][item['size']]:
            print("\t" + str(hash_prefix))
            
        print()
        
        

## Main function, starts everything off
#    
def main():

    # Information about this program
    program_info = {
    
        # Program and Contact Info
        'name':'Pwned Passwords Padding Sniffer',
        'version': '1.0',
        'author':'Matt Weir',
        'contact':'cweir@vt.edu',
        'filename': None,
        'time_interval': 10,
        'interface': None,
    }
    
    # Parsing the command line
    if not parse_command_line(program_info):
        # There was a problem with the command line so exit
        print("Exiting...",file=sys.stderr)
        return
        
    print(program_info['name'],file=sys.stderr)
    print("Version: " + str(program_info['version']),file=sys.stderr)
    print('',file=sys.stderr)
   
    # Create the TrainingSniffer instance
    sniffer = TrainingSniffer(program_info['time_interval'], 1, program_info['interface'])
              
    # Open the training file
    hash_stats = load_training_file(program_info['filename'])
    
    # Used to specify if the queries should continue
    keep_sniffing = True
    
    # Start sniffing the pwned passwords service
    try:
        while (keep_sniffing):            
            
            # Start collecting statistics on the queries
            results = sniffer.start_training()
            
            process_results(hash_stats, results)
            
            keep_sniffing = False
            
    except Exception as msg:
        print ("Exception: " + str(msg))            
    

if __name__ == "__main__":
    main()