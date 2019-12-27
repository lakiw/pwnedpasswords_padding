#!/usr/bin/env python3


################################################################################
# Contains functionality to interact with the scapy library and perform
# packet sniffing
#
################################################################################


import sys
import scapy.all as scapy


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

    #if capture interface is not specified
    if interface == None:
        scapy.sniff(store=False, prn=process_packets, timeout = time)
    else:
        scapy.sniff(iface=interface, store=False, prn=process_packets, timeout = time)

    
    #captured_sessions = extract_pp_sessions()       
        
    return captured_sessions


## Handler when a sniffed packet comes in
#
def process_packets(packet):
    try:
        print(packet[0][1].src)
    except (KeyboardInterrupt, SystemExit):
        sys.exit()
    except:
        pass


## Attempt to extract pwned password sessions from a capture
#
# Note: pyshark doesn't stop live captures which was a new learning experience
#       for me, so need to save and iterate through the list. Should work
#       for a PoC but may end up having to go back to scapy for packet capture    
def extract_pp_sessions(capture):
    #print("Parsing sessions",file=sys.stderr)
    capture_size = len(capture)
    #print("Number of packets captures: " + str(capture_size), file=sys.stderr)

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
                    #print("Found a potential pwned passwords request!")
                    # Create a new item for the session and initialize it
                    pp_sessions[session_id] = {'packet_ids':[i], 'num_packets':1, 'size':0,'dst_ip':str(capture[i].ip.dst),'sequence':{capture[i].tcp.seq:i}, 'finished':False}
              
                # Check if a session was associated with a pp request. Note this
                # could have false negatives if the client hello arrives out of order
                # but this logic will need to be revamped significantly anyways to
                # deal with things like TCP retransmissions, so going to leave that
                # for a later version.
                elif session_id in pp_sessions:
                    
                    # Only save the responses from the pp server
                    if str(capture[i].ip.src) == pp_sessions[session_id]['dst_ip']:
                    
                        # Don't parse repeated packets (since TCP)
                        if capture[i].tcp.seq in pp_sessions[session_id]['sequence']:
                            continue               
                        
                        pp_sessions[session_id]['sequence'][capture[i].tcp.seq] = i
                    
                        # Verify there is application data in this payload
                        # May have false positives, since not really parsing the
                        # full TLS header the correct way
                        
                        # Get the raw payload
                        raw_payload = capture[i].tcp.payload.replace(':','')
                        data_index = raw_payload.find('170303')
                        
                        if data_index != -1:
                            pp_sessions[session_id]['packet_ids'].append(i)

                        # There can be multiple https application data segments
                        # in a single TCP packet
                        while data_index != -1:
                            pp_sessions[session_id]['num_packets'] += 1
                            app_string = raw_payload[data_index+6:data_index+10]
                            app_size = int(app_string, 16)

                            pp_sessions[session_id]['size'] += app_size
                            
                            raw_payload = raw_payload[data_index + 10 + (app_size*2)]
                            data_index = raw_payload.find('170303')
                        
                        
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
            #print(str(msg))
            continue
        
    # The list of all sessions where valid statistics have been collected    
    captured_sessions = []
    
    # Add the valid sessions to the return value
    for session in pp_sessions.values():
        if session['finished'] == True:
            captured_sessions.append((session['size'],session['num_packets']))

    return captured_sessions