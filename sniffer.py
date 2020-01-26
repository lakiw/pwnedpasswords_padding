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
import traceback

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
        type = int,
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
    
    # The search space to use when trying to find near misses of hash prefixes
    parser.add_argument(
        '--search_range',
        '-s',
        help = 'The default (in bytes) range to search to find near misses for hash prefixes ' +str(program_info['search_range']), 
        metavar = 'BYTES',
        required = False,
        type = int,
        default = program_info['search_range']
    )
    
    # Read a pcap file vs. sniff traffic on the wire
    parser.add_argument(
        '--pcap_file',
        '-p',
        help = 'Read traffic from a pcap file vs. sniff on the wire. Incompatible with the -i flag', 
        metavar = 'FILE_NAME',
        required = False,
        default = program_info['pcap_file']
    )
      
    # Parse all the args and save them    
    args=parser.parse_args() 
    
    program_info['filename'] = args.filename
    program_info['time_interval'] = args.time_interval
    program_info['interface'] = args.interface
    program_info['search_range'] = args.search_range
    program_info['pcap_file'] = args.pcap_file
    

    return True 
    
  
## Loads a training session from disk
#
# Values:
#
#    filename: The name of the training file to open
# 
def load_training_file(filename):
    
    hash_stats = {}

    with open(filename, 'r') as training_file:
    
        # Walk through each line in the training file which should be a json structure
        for line in training_file:
            
            # Convert the line to a JSON structure
            data = json.loads(line)   

            # Should only have one hash_prefix per line, but might as well make
            # it a loop
            for hash_prefix in data:
            
                # Ideally the number of packets shouldn't matter if the
                # TLS traffic analyzer worked correctly, but there still are
                # a lot of gaps in how it works, so right now the lower the number
                # of packets in a session, the more confidence we have in a 
                # categorization
                for num_packets in data[hash_prefix]:
                    
                    if int(num_packets) not in hash_stats:
                        hash_stats[int(num_packets)] = {}
                    
                    for size in data[hash_prefix][num_packets]:
                        if int(size) not in hash_stats[int(num_packets)]:
                            hash_stats[int(num_packets)][int(size)] = {}
                            
                        if hash_prefix not in hash_stats[int(num_packets)][int(size)]:
                            hash_stats[int(num_packets)][int(size)][hash_prefix] = data[hash_prefix][num_packets][size]
                        else:
                            hash_stats[int(num_packets)][int(size)][hash_prefix] += data[hash_prefix][num_packets][size]
            
    return hash_stats        


## Search the training list for a match for the size of the session
#
# Values:
#
#     hash_stats: The training data (python dictionary)
#
#     num_packets: The number of applicaton data packets in the session
#
#     size: The size of the session to perform a lookup on
#
# Return:
#   None: Nothing found
#   Dictionary: {hash_prefix:num_found_in_training}
#
def lookup_in_training(hash_stats, num_packets, size):

    if num_packets in hash_stats:
       if size in hash_stats[num_packets]:
            return hash_stats[num_packets][size]
            
    return None
    
  
## Attempts to identify pwned password hash prefixes
#
def process_results(hash_stats, results, search_range = 10, min_limit_for_high = 10):
    
    # The total sessions that were sniffed:
    total_sniffed = 0
    
    # The total sessions that were categorized high:
    total_categorized_high = 0
    
    # Dictionary is keyed by number of packets
    guessed_prefixes = {}
    
    # Loop through all of the results
    for num_packets in results:
        for size in results[num_packets]:
            count = results[num_packets][size]
            total_sniffed += count
            
            # Loop through the range, tring to find matches
            for lookup_size in range(size - search_range, size + search_range + 1):
            
                found_results = lookup_in_training(hash_stats, num_packets, lookup_size)
            
                # Found one or more matches in the training set
                if found_results != None:
                    
                    # loop through all the hash prefixes found in the results
                    for hash_prefix in found_results.keys():
                    
                        num_found = found_results[hash_prefix]
                    
                        ## Create the classification of confidence in results
                        
                        # High confidence
                        #
                        # -The exact size was seen in the training set, (this isn't from a range search_distance)
                        # -The number of times it was seen was equal or above the threshold
                        if (lookup_size == size) and (num_found >= min_limit_for_high):
                            cat = 'high'
                            total_categorized_high += count
                            
                        # Medium confidence
                        #
                        # -The exact size was seen in the training set, (this isn't from a range search_distance)
                        # -The number of times it was seen was below the threshold
                        elif (lookup_size == size):
                            cat = 'medium'
                        
                        # Low confidence
                        #
                        # Everything else (aka it was seen in a range search)
                        else:
                            cat = 'low'
                        
                        ## Save the results
                        
                        # Intitialize the key if needed
                        if num_packets not in guessed_prefixes:
                            guessed_prefixes[num_packets] = {}
                            
                        # Initialize the size key if needed
                        if size not in guessed_prefixes[num_packets]:
                            guessed_prefixes[num_packets][size] = {'high':{}, 'medium': {}, 'low': {}}            
                        
                        # Check if the prefix was saved for a different category and only save the highest
                        if cat == 'high':
                            if hash_prefix in guessed_prefixes[num_packets][size]['medium']:
                                del guessed_prefixes[num_packets][size]['medium'][hash_prefix]
                            if hash_prefix in guessed_prefixes[num_packets][size]['low']:
                                del guessed_prefixes[num_packets][size]['low'][hash_prefix]
                        
                        if cat == 'medium':
                            if hash_prefix in guessed_prefixes[num_packets][size]['low']:
                                del guessed_prefixes[num_packets][size]['low'][hash_prefix]                    
                            if hash_prefix in guessed_prefixes[num_packets][size]['high']:
                                continue
                                
                        if cat == 'low':                  
                            if hash_prefix in guessed_prefixes[num_packets][size]['high']:
                                continue
                            elif hash_prefix in guessed_prefixes[num_packets][size]['medium']:
                                continue
                        
                        # Now really save the results
                        guessed_prefixes[num_packets][size][cat][hash_prefix] = num_found                     
        
    # Print top level results
    print("Number of PwnedPasswords Lookups Parsed:            " + str(total_sniffed))
    print("Number of Lookups Categorized with High Likelyhood: " + str(total_categorized_high))
    print()
    print("Captured sessions sorted by number of TLS application data sections identified")
    print("Due to limitations of the current TLS sniffer, the lower number of sections, the higher confidence in the results")
    print("----------------------------------------------------------")
    
    for num_packets in sorted (results.keys()): 
        print("------ " + str(num_packets) + " TLS Application Data Sections:----------------")
        print()
        
        if num_packets not in guessed_prefixes:
            print("\tAll sessions containing this number of data sections were uncategoriezed")
            print()
            continue
        
        for size in sorted(results[num_packets]):
            print("Size of Session: " + str(size))
            print()
            
            # No results found for this size
            if size not in guessed_prefixes[num_packets]:
                print("\tAll sessions of this size were uncategoriezed")
                print()
                continue
            
            # Print the high likelyhood results
            if len(guessed_prefixes[num_packets][size]["high"]) != 0:
                print("\tHigh Likelyhood Prefixes:")
                print("\t----------------------------")
                for hash_prefix in sorted(guessed_prefixes[num_packets][size]['high']):
                    print("\t" + str(hash_prefix))
                print()
                    
            # Print the medium likelyhood results
            if len(guessed_prefixes[num_packets][size]["medium"]) != 0:
                print("\tMedium Likelyhood Prefixes:")
                print("\t----------------------------")
                for hash_prefix in sorted(guessed_prefixes[num_packets][size]['medium']):
                    print("\t" + str(hash_prefix))
                print()
                
            # Print the low likelyhood results
            if len(guessed_prefixes[num_packets][size]["low"]) != 0:
                print("\tLow Likelyhood Prefixes:")
                print("\t----------------------------")
                for hash_prefix in sorted(guessed_prefixes[num_packets][size]['low']):
                    print("\t" + str(hash_prefix))
                print()
    
    return
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
        'search_range': 10,
        'pcap_file': None,
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
    sniffer = TrainingSniffer(program_info['time_interval'], 1, program_info['interface'], program_info['pcap_file'])
              
    # Open the training file
    hash_stats = load_training_file(program_info['filename'])
    
    # Used to specify if the queries should continue
    keep_sniffing = True
    
    # Start sniffing the pwned passwords service
    try:
        while (keep_sniffing):            
            
            # Start collecting statistics on the queries
            results = sniffer.start_training()
            
            process_results(hash_stats, results, program_info['search_range'])
            
            keep_sniffing = False
            
    except Exception as msg:
        traceback.print_exc()
        print ("Exception: " + str(msg))            
    

if __name__ == "__main__":
    main()