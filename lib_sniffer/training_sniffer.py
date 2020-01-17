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
from scapy.sessions import IPSession
import traceback

    
## Used for creating full duplex Scapy sessions
#
# Copied from https://pen-testing.sans.org/blog/2017/10/13/scapy-full-duplex-stream-reassembly
#
def full_duplex(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                sess = str(sorted(["TCP", p[scapy.IP].src, p[scapy.TCP].sport, p[scapy.IP].dst, p[scapy.TCP].dport],key=str))
            elif 'UDP' in p:
                sess = str(sorted(["UDP", p[scapy.IP].src, p[scapy.UDP].sport, p[scapy.IP].dst, p[scapy.UDP].dport] ,key=str))
            elif 'ICMP' in p:
                sess = str(sorted(["ICMP", p[scapy.IP].src, p[scapy.IP].dst, p[scapy.ICMP].code, p[scapy.ICMP].type, p[scapy.ICMP].id] ,key=str)) 
            else:
                sess = str(sorted(["IP", p[scapy.IP].src, p[scapy.IP].dst, p[scapy.IP].proto] ,key=str)) 
        elif 'ARP' in p:
            sess = str(sorted(["ARP", p[scapy.ARP].psrc, p[scapy.ARP].pdst],key=str)) 
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    return sess    
    
    
## Putting functionality for the sniffer to train a PP hash prefix predictor
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
            break
        
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

        ## Capture packets for a given time before processing them as a batch
        #        
        # if capture interface is not specified
        if self.interface == None:
            capture = scapy.sniff(store = True, timeout = self.interval_time, session = IPSession)
        else:
            capture = scapy.sniff(iface = self.interface, store = True, timeout = self.interval_time, session = IPSession)
        
        ## Create the full duplex matching of Scapy sessions
        #
        scapy_sessions = capture.sessions(full_duplex) 
        
        ## Extract the pwned password lookups from the captured TCP sessions
        #
        pp_sessions = self._extract_pp_sessions(scapy_sessions)    
        
        traffic_analysis = []
        
        for session in pp_sessions:
            payload_size, payload_chunks = self._calculate_payload_size(session['packets'])

        return traffic_analysis
    

    ## Extracts pwned password sessions from scapy sniffed traffic
    #
    def _extract_pp_sessions(self, scapy_sessions):
        
        pp_sessions = []
        # Loop through all of the sessions and identify if they contain abs
        # connection to the pwned passwords server
        for session in scapy_sessions.values():
            # Not a TCP session that this tool can parsed
            if not self._is_valid_tcp_session(session):
                continue
            # Search for the cert for the pwned password session
            start_id = self._detect_pp_cert(session)
            
            # If this session isn't identified as a PP session, skip it
            if start_id == None:
                continue
                
            # Parse the full session to figure out if we collected all the
            # packets we are interested in            
            parsed_session = self._order_session(session, start_id[1])
            
            # Didn't parse the full session correctly.
            # Did not sniff all the packets.
            if parsed_session == None:
                continue
                
            # Add the data to pp_sessions
            session_data = {
                'packets':parsed_session
            }
            pp_sessions.append(session_data)
          
        return pp_sessions
        
    
    ## Identify sessions to skip further parsing
    #
    # Note: Skipping it could be "non-TCP session", or unsupported
    #       TCP artificats. An example of that currently would be TCP
    #       fragmentation
    #
    # Values:
    #    session: A Scapy collected session
    #
    # Return:
    #     True: if this session can be parsed by the current TCP parser
    #
    #     False: If this session is not TCP, and/or can not be parsed
    #
    def _is_valid_tcp_session(self, session):
    
        for packet in session:
        
            # Found a non-TCP session
            if scapy.TCP not in packet:
                return False
            
            # Check to see if it is an IP packet
            # I know, if it's TCP it will likely be IP, but who knows it
            # could be a really weird network, and the check is easy
            if scapy.IP not in packet:
                return False
                
            ## Currently not supporting IP fragmentation
            #
            # That being said, the Scapy IPSession sniffer session "should"
            # handle fragment reassembly
            #
            if packet[scapy.IP].frag != 0:
                print("Fragment packet discovered. Marking session as invalid")
                return False
                
        return True
        
    
    ## Looks for the pwned passwords api URL in the TLS certificates
    #
    # Values:
    #    session: A Scapy collected session
    #
    # Return:
    #     None: if a PwnedPasswords TLS cert was not found
    #
    #     (Sequence_Num, Ack_Num): if a pwned passwords TLS cert was found
    #
    def _detect_pp_cert(self, session):

        for packet in session:
                
            # Easier to look through the raw hex of the packet when parsing it
            try:
                raw_payload = packet.load.hex()
            except:
                # There is no data payload of the packet
                continue
            
            # Look for pwned password session
            # Translates into "api.pwnedpasswords.com". This info is seen in the client hello packet
            if raw_payload.find("6170692e70776e656470617373776f7264732e636f6d") != -1:
                # print("Found PP Session!")
                
                return (packet[scapy.TCP].seq, packet[scapy.TCP].ack)
            
        return None
        
    
    ## Orders a session to verify Scapy collected all of the packets
    #
    def _order_session(self, session, seq):
        
        ordered_session = []
        
        # Loop through all of the packets until we hit the fin packet
        keep_looping = True
        while keep_looping:
            keep_looping = False
            for packet in session:
                if packet[scapy.TCP].seq == seq:
                    ordered_session.append(packet)
                    
                    ## If we have finished parsing this stream
                    if packet[scapy.TCP].flags == "FA":
                        # print("Finished parsing a session")
                        return ordered_session
                    
                    ## Else calculate the next sequence number to look for
                    try:
                        seq += len(packet[scapy.Raw])
                    except:
                        # For some reason, some scapy packets don't have the
                        # "raw" layer.
                        return None
                        
                    keep_looping = True
              
        return None
    
    
    ## Calculates the size of the payload of the server's response to 
    #  a query to the Pwned Passwords server
    #
    # Variables:
    #    session: A parsed pp session of the server responses
    #
    # Return Values:
    #    size, num_data_sections: The payload size, and the number of 
    #                             data sections parsed
    #
    def _calculate_payload_size(self, session):
    
        # Number of data chunks parsed
        # Note: a single packet can have multiple data chunks
        # Note2: This is important since data chunks can have a checksum
        #        and may have padding
        num_data_chunks = 0
        
        # Size of payload data
        payload_size = 0
    
        for packet in session:
        
            # Easier to look through the raw hex of the packet when parsing it
            try:
                raw_payload = packet.load.hex()
            except:
                # There is no data payload of the packet
                continue
            
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
                
                num_data_chunks += 1
                
                app_string = raw_payload[data_index+7:data_index+11]  
                if len(app_string) == 0:
                    return None, None
                
                app_size = int(app_string, 16)
                
                #print(raw_payload)
                #print("App String: " + str(app_string))
                #print("Size: " + str(app_size))
                #input("Hit Enter")
                
                payload_size += app_size
                
                if len(raw_payload) < data_index + 11 + 2 +(app_size*2):
                    print("Hmmm, should be throwing an exception")
                
                # Advance to the next chunk and see if there is more data to process
                try:
                    raw_payload = raw_payload[data_index + 11 + 2 + (app_size*2):]
                except:
                    print("Packet data did not exist")
                    return None, None
                    
                data_index = raw_payload.find('170303')
                    
    
        # If no data was observed
        if payload_size == 0:
            return None, None
            
        # Take out sha checksum from payload size
        payload_size = payload_size - (20 * num_data_chunks)
            
        print(str(payload_size) + " : " + str(num_data_chunks))
        return payload_size, num_data_chunks
        
        
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
    