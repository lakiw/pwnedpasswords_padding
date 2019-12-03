#!/usr/bin/env python3


################################################################################
# Contains functionality to interact with the scapy library and perform
# packet sniffing
#
################################################################################


import sys
import pyshark


## Sniffs traffic on an interface and tries to identify pwnedpasswords
#  hash prefix lookup sessions
#
# Variables:
#
#   time: The time in seconds to sniff traffic before processing it
#
#   interface: The interface to sniff traffic on. If not specified, will
#              capture on all interfaces
#
def sniff_pwnedpasswords_sessions(time = 5, interface = None):

    if interface != None:
        capture = pyshark.LiveCapture(bpf_filter='tcp port 443', interface=interface)
    else:
        capture = pyshark.LiveCapture(bpf_filter='tcp port 443')
    capture = pyshark.LiveCapture(bpf_filter='tcp port 443')
    capture.sniff(timeout= time)
    extract_pp_sessions(capture)
    

## Attempt to extract pwned password sessions from a capture
#
# Note: pyshark doesn't stop live captures which was a new learning experience
#       for me, so need to save and iterate through the list. Should work
#       for a PoC but may end up having to go back to scapy for packet capture    
def extract_pp_sessions(capture):
    print("Parsing sessions",file=sys.stderr)
    capture_size = len(capture)
    print("Number of packets captures: " + str(capture_size), file=sys.stderr)

    # Holds the ranges for the sessions idenfied as potentially querying 
    # pwned passwords. Key is session_id to allow for querying out of order
    # sessions as they come in
    pp_sessions = {}
    for i in range(0, capture_size):
        
        try:
            # Grab the session ID
            session_id = int(capture[i].tcp.stream)
        
            try:
            
                # Looking for api.pwnedpasswords.com in hex
                # Yes, this will totally have false positives if for example that
                # shows up in a normal html string, but with filtering on port
                # tcp 443, that should limit the number of false positives
                if capture[i].tcp.payload.find("61:70:69:2e:70:77:6e:65:64:70:61:73:73:77:6f:72:64:73:2e:63:6f:6d") != -1:
                    print("Found a potential pwned passwords request!")
                    # Create a new item for the session and initialize it
                    pp_sessions[session_id] = {'packet_ids':[i], 'num_packets':1, 'size':0,'dst_ip':str(capture[i].ip.dst), 'finished':False}
              
                # Check if a session was associated with a pp request. Note this
                # could have false negatives if the client hello arrives out of order
                # but this logic will need to be revamped significantly anyways to
                # deal with things like TCP retransmissions, so going to leave that
                # for a later version.
                elif session_id in pp_sessions:
                    # Only save the responses from the pp server
                    if str(capture[i].ip.src) == pp_sessions[session_id]['dst_ip']:
                        pp_sessions[session_id]['packet_ids'].append(i)
                        pp_sessions[session_id]['num_packets'] += 1
                        pp_sessions[session_id]['size'] += len(capture[i].tcp.payload)
                        
                        
            # No TCP Payload found. Still useful to find the fin/ack of a
            # finished session
            except:
                # Check to see if the session is ending
                # Two of these should occur, (from both client and server)
                # but just seeing one is good enough
                if int(capture[i].tcp.flags,16) == 0x011:
                    if session_id in pp_sessions:
                        pp_sessions[session_id]['finished'] = True
            
        except Exception as msg:
            print(str(msg))
            continue
        

    for session in pp_sessions.values():
        if session['finished'] == True:
            print(session['size'])

