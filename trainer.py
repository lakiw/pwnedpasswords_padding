#!/usr/bin/env python3


########################################################################################
#
# Name: Trains a sniffer on what non-padded responses correspond to submitted
#       hash prefixes.
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
#  trainer.py
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

# Local imports
from lib_query.query_process import launch_query_process
from lib_sniffer.sniffer_process import launch_sniffer_process
from lib_query.hash_prefix import HashPrefix

       
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
    
    # filename to save the results to. If not specified, output to stdout
    parser.add_argument(
        '--filename',
        '-f',
        help = 'The filename to save results to. If not specified, will output to stdout', 
        metavar = 'FILE_NAME',
        required = False,
        default = program_info['filename']
    )
    
    # Start at the specified index, (vs 0), and append to a training set if it
    # already exists
    parser.add_argument(
        '--start_prefix',
        '-s',
        help = 'Starts querying from the specified prefix, and will append to a training file if it already exists', 
        metavar = 'START_HASH_PREFIX',
        required = False,
        default = program_info['start_prefix']
    )
    
    # The default time chunks the sniffer should sniff for
    parser.add_argument(
        '--time_interval',
        '-t',
        help = 'The default time interval (seconds) the sniffer should run for when training on each hash prefix. Default is ' +str(program_info['time_interval']), 
        metavar = 'SECONDS',
        required = False,
        default = program_info['time_interval']
    )
    
    # The minimum number of samples to collect for each hash prefix
    parser.add_argument(
        '--num_samples',
        '-n',
        help = 'The minimum number of samples to collect for each hash previx. Default is ' +str(program_info['num_samples']), 
        metavar = 'MINIMUM_SAMPLES',
        required = False,
        default = program_info['num_samples']
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
    program_info['start_prefix'] = args.start_prefix
    program_info['time_interval'] = args.time_interval
    program_info['num_samples'] = args.num_samples
    program_info['interface'] = args.interface

    return True 
  
  
## Main function, starts everything off
#    
def main():

    # Information about this program
    program_info = {
    
        # Program and Contact Info
        'name':'Pwned Passwords Padding Trainer',
        'version': '1.0',
        'author':'Matt Weir',
        'contact':'cweir@vt.edu',
        'filename': None,
        'start_prefix': None,
        'time_interval': 5,
        'num_samples': 20,
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
    
    # Spawn off the querying process
    query_ptoc_queue = Queue()
    query_ctop_queue = Queue()
    query_process = Process(target=launch_query_process, args=("https://api.pwnedpasswords.com/range/", query_ptoc_queue, query_ctop_queue,))
    query_process.start()
    
    # Spawn off the sniffer process
    sniffer_ptoc_queue = Queue()
    sniffer_ctop_queue = Queue()
    sniffer_process = Process(target=launch_sniffer_process, args=(program_info['time_interval'], program_info['num_samples'], program_info['interface'], sniffer_ptoc_queue, sniffer_ctop_queue,))
    sniffer_process.start()
    
    # Create the hash_prefix object that will specify the current prefix to
    # target
    
    # If static_prefix was specified on the command line:
    if program_info['start_prefix'] != None:
        initial_prefix = program_info['start_prefix']
        prefix_len = len(program_info['start_prefix'])
    
    # Otherwise, start at the default '00000'
    else:
        initial_prefix = '00000'
        prefix_len = 5
        
    hash_prefix = HashPrefix(initial= initial_prefix, length= prefix_len)
    
    # Used to specify if the queries should continue
    keep_querying = True
    
    # Start querying the pwned passwords service
    while (keep_querying):
        # Start querying the hash prefix
        query_ptoc_queue.put(hash_prefix.get_value())
        
        # Wait a short delay to give the query time to start
        time.sleep(0.2)
        
        # Start collecting statistics on the queries
        sniffer_ptoc_queue.put({'action':'scan'})
        
        # Collect and save the data
        results = sniffer_ctop_queue.get()
        print(str(hash_prefix.get_value()) + " : " + str(results))
        
        # Increment the hash prefix
        # If we are at the end of the keyspace, stop querying
        if hash_prefix.increment() != 0:
            keep_querying = False
    
    
    # Clean up and exit
    query_process.join()
    sniffer_process.join()
    
    

    
if __name__ == "__main__":
    main()