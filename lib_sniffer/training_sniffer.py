#!/usr/bin/env python3


################################################################################
# Responsible for sniffing https encrypted traffic to pwnedpasswords and 
# recording the size of each session
#
################################################################################


# Global imports
import sys
import time
import scapy.all as scapy
from binascii import hexlify

    
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
    
    
    ## Sniff the network interface and collect statistics on the pp sessions
    #
    def start_training(self):
        saved_sessions = []
        
        # Keep trying to collect samples untill it has collected the minimum
        # amount
        while len(saved_sessions) < self.num_samples :
            #print("Sniffing Wire")
            saved_sessions.extend(self.sniff_pwnedpasswords_sessions())
            #print(saved_sessions)
        
        return self._format_results(saved_sessions)
        
               
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
    def sniff_pwnedpasswords_sessions(self):

        # Save sessions based on source port of the client
        sessions = {}

        ## Capture packets for a given time before processing them as a batch
        #
        
        # if capture interface is not specified
        if self.interface == None:
            capture = scapy.sniff(store = True, timeout = self.interval_time)
        else:
            capture = scapy.sniff(iface = interface, store = True, timeout = self.interval_time)

        ## Process packets
        #
        #i  = 1
        for packet in capture:
            #print("Processing Packet: " + str(i))
            #i+= 1
        
            # Only look at TCP packets
            if scapy.TCP not in packet:
                continue
                
            # Get the TCP src and dst ports for the packet
            src_port = str(packet[scapy.TCP].sport)
            dst_port = str(packet[scapy.TCP].dport)
            
            # Easier to look through the raw hex of the packet when parsing it
            raw_payload = scapy.raw(packet[0]).hex()
            # Look for pwned password session
            # Translates into "api.pwnedpasswords.com". This info is seen in the client hello packet
            if raw_payload.find("6170692e70776e656470617373776f7264732e636f6d") != -1:
            
                # Could be a packet retransmit or something, but should not trust this session for training
                if src_port in sessions:
                    # print("Warning, see multiple sessions to pwned passwords using the same tcp src port. May create unreliable results")
                    sessions[src_port]['valid'] = False
                
                else:
                    sessions[src_port] = {'num_data_chunks':0, 'size':0,'dst_ip':str(packet[scapy.IP].dst), 'sequence':{}, 'finished':False, 'valid':True}
                
            # Check to see if this has data to be processed
            # Looking at the dst port since it will be from the server to the client
            elif dst_port in sessions:
            
                # Check to make sure the packet isn't repeated
                sequence_num = packet[scapy.TCP].seq
                if sequence_num in sessions[dst_port]['sequence']:
                    continue
                    #print("Duplicate sequence number found")
                    #sessions[dst_port]['valid'] = False
                
                sessions[dst_port]['sequence'][sequence_num] = True
                
                # Now look to see if there is a data segment that needs to be accounted for
                #
                # PoC Note: This will only work for TLS version 1.2
                # May have false positives as well, haven't created a full
                # TLS packet parser which would be needed to avoid doing
                # a simple string search
                #
                # 0x17 = Content Type Application Data
                # 0x0303 = Version TLS 1.2  
                data_index = raw_payload.find('170303')
                
                # There can be multiple application data sections in a single packet
                while data_index != -1:
                    sessions[dst_port]['num_data_chunks'] += 1
                    
                    app_string = raw_payload[data_index+6:data_index+10]  
                    if len(app_string) == 0:
                        sessions[dst_port]['valid'] = False
                        break
                    
                    app_size = int(app_string, 16)
                    
                    sessions[dst_port]['size'] += app_size
                    
                    # Advance to the next chunk and see if there is more data to process
                    raw_payload = raw_payload[(data_index + 10 + (app_size*2)):]
                    data_index = raw_payload.find('170303')

                # Check for a Fin/Ack to signify the session completed correctly
                if packet[scapy.TCP].flags == "FA":
                    sessions[dst_port]['finished'] = True
                
                # Check for fragmented packets (since we currently are not handling them
                if packet[scapy.IP].frag != 0:
                    print("Fragment packet discovered. Marking session as invalid")
                    sessions[dst_port]['valid'] = False
                
        # The list of all sessions where valid statistics have been collected    
        captured_sessions = []
    

        # Add the valid sessions to the return value
        for stream in sessions.values():
            if stream['finished'] == True:
                if stream['valid'] == True:
                    captured_sessions.append((stream['size'],stream['num_data_chunks']))
                    
        return captured_sessions
        
        
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
    