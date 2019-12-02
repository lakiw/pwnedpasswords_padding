#!/usr/bin/env python3


########################################################################################
#
# Name: Querys pwned passwords service and saves the result
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
#  query_pwned_passwords.py
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

# Local imports
from lib_query.pwned_passwords_api import get_list_for_hash
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
      
    # Parse all the args and save them    
    args=parser.parse_args() 

    return True 
  
  
## Main function, starts everything off
#    
def main():

    # Information about this program
    program_info = {
    
        # Program and Contact Info
        'name':'Pwned Passwords Query Agent',
        'version': '1.0',
        'author':'Matt Weir',
        'contact':'cweir@vt.edu',

    }
    
    # Parsing the command line
    if not parse_command_line(program_info):
        # There was a problem with the command line so exit
        print("Exiting...",file=sys.stderr)
        return
        
    print(program_info['name'],file=sys.stderr)
    print("Version: " + str(program_info['version']),file=sys.stderr)
    print('',file=sys.stderr)
    
    # Initialize the hash prefix to start doing lookups on
    hash_prefix = HashPrefix()
    
    
    while (hash_prefix.increment() == 0):
        status_code, content = get_list_for_hash('https://api.pwnedpasswords.com/range/',hash_prefix.get_value())
        print(hash_prefix.get_value() + '\t' + str(status_code) + "\t" + str(len(content)))
  
    
if __name__ == "__main__":
    main()