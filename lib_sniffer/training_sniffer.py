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
    def __init__(self, interval_time, num_samples, interface = None, pcap_file = None):

        self.interval_time = interval_time
        self.num_samples = num_samples
        self.interface = interface
        self.pcap_file = pcap_file
    
    
    ## Sniff the network interface and collect statistics on the pp sessions
    #
    def start_training(self):
        saved_sessions = []
        
        # Keep trying to collect samples untill it has collected the minimum
        # amount
        while len(saved_sessions) < self.num_samples :
            #print("Sniffing Wire")
            saved_sessions.extend(self.sniff_pwnedpasswords_sessions())
            
            # Quick bail out if we are using a pcap file vs. sniffing the wire
            if self.pcap_file != None:
                print("Done parsing the pcap file")
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

        ## If reading from a pcap file vs. sniffing the wire
        if self.pcap_file != None:
            try:
                capture = scapy.rdpcap(self.pcap_file)
            except:
                print("Error trying to process pcap file. Exiting")
                return None

        ## Capture packets for a given time before processing them as a batch
        #        
        # if capture interface is not specified
        elif self.interface == None:
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
            
            if payload_size != None:
                traffic_analysis.append((payload_size, payload_chunks))

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
            client_tcp_seq, server_tcp_seq = self._detect_pp_cert(session)
            
            # If this session isn't identified as a PP session, skip it
            if server_tcp_seq == None:
                continue
                
            # Parse the full session to figure out if we collected all the
            # packets we are interested in            
            parsed_sessions = self._order_session(session, client_tcp_seq, server_tcp_seq)
            
            # Didn't parse the full session correctly.
            # Did not sniff all the packets.
            if parsed_sessions == None:
                continue
                
            # Add the data to pp_sessions
            for individual_lookup in parsed_sessions:
                session_data = {
                    'packets':individual_lookup
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
    #     None, None: if a PwnedPasswords TLS cert was not found
    #
    #     Sequence_Num, Ack_Num: if a pwned passwords TLS cert was found
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
                
                return packet[scapy.TCP].seq, packet[scapy.TCP].ack
            
        return None, None
        
    
    ## Orders a session to verify Scapy collected all of the packets
    #
    # Note: Modified this since there may be multiple PP lookups in a signle
    #       session, so now it returns a list of all lookups, and those lookups
    #       contain a list of all the packets from the PP server associated with
    #       a particular hash lookup query.
    #
    def _order_session(self, session, client_seq, server_seq):
        
        ordered_sessions = []
        
        # Loop through all of the packets until we hit the fin packet
        keep_looping = True
        while keep_looping:
            individual_lookup = []
            keep_looping = False
            for packet in session:
                if packet[scapy.TCP].seq == server_seq:
                    individual_lookup.append(packet)
                    
                    ## If we have finished parsing this stream
                    if packet[scapy.TCP].flags == "FA":
                        # print("Finished parsing a session")
                        
                        # Save the last individual_lookup before returning
                        # all of the lookups
                        ordered_sessions.append(individual_lookup)
                        
                        return ordered_sessions
                    
                    ## Else calculate the next sequence number to look for
                    try:
                        server_seq += len(packet[scapy.Raw])
                    except:
                        # For some reason, some scapy packets don't have the
                        # "raw" layer.
                        return None
                        
                    keep_looping = True
                    
        # Temporary being used for debugging
        #if len(ordered_session) > 10:
        #    return ordered_session
            
        print("Pwned Password session detected but dropped due to missing packets")
        return None
    
    
    ## Calculates the size of the payload of the server's response to 
    #  a query to the Pwned Passwords server
    #
    # Variables:
    #    session: A parsed pp session of the server responses
    #
    #    checksum_size: The size of the checksum for each data chunk
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
        
        # If the encryption mode was detected
        known_iv_padding = False
    
        for packet in session:
        
            # Easier to look through the raw hex of the packet when parsing it
            try:
                raw_payload = packet.load.hex()
            except:
                # There is no data payload of the packet
                continue
             
            # Now look to see if there is a data segment that needs to be accounted for
            #
            payload_info = self.identify_tls_payload_type(raw_payload)
            #print(payload_info)

            # There can be multiple application data sections in a single packet
            while payload_info != None:
                
                # If this is a server hello packet (identify the encryption mode)
                if (payload_info['type'] == 16) and (payload_info['sub_type'] == 'server_hello'):
                    known_iv_padding, iv_size, checksum_size = self._identify_encrytion_overhead(payload_info['cipher'])
                
                # If an application data payload
                elif payload_info['type'] == 17:
                
                    # Sanity check to make sure we detected the cipher suite being used
                    if known_iv_padding != True:
                        print("Unknown cipher suite, aborting this session")
                        return None, None
                        
                    num_data_chunks += 1
                    
                    # Add to the payload size, but remove the overhead of the IV and checksum
                    if payload_info['size'] < (checksum_size + iv_size):
                        #print("Hmm, the payload seems too small")
                        payload_size += payload_info['size']
                    
                    # Remove the overhead of the IV and checksum
                    else:
                        payload_size += (payload_info['size'] - checksum_size - iv_size)
                         
                # Advance to the next chunk and see if there is more data to process
                try:
                    raw_payload = raw_payload[payload_info['next_section']:]
                except:
                    print("Packet data did not exist")
                    return None, None
                    
                payload_info = self.identify_tls_payload_type(raw_payload)        
         
        # If no data was observed
        if payload_size <= 0:
            return None, None           
           
        #print(str(payload_size) + " : " + str(num_data_chunks))
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
        
    ## Returns if the ciphersuite was identified, along with the overhead of
    #  the MAC and IV for the ciphersuite
    #
    # Return
    #     False, 0, 0: if an error occured, or cipher suite isn't supported
    #
    #     True, IV, MAC: If it was processed correctly
    #
    def _identify_encrytion_overhead(self, cipher_mode):
    
        # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        if cipher_mode == 'c02b':
            #iv = 4 (salt) + 8 (explicit nonce) + 9 (additional authentication data AAD)
            #mac = 16 (sha256, but it seems only to store half)
            return True, 4+8+9, 16
        else:
            print ("Unsupported cipher suite")
            return False, 0 , 0
    
    
    ## Will identify the TLS payload type for the packet_section
    #
    # Returns a dictionary containing info about the payload type
    #
    #     Top level key is type. Other keys in dictionary depend on type.
    #         aka 'type':16 = TLS Hello handshake
    #             'type':17 = TLS application data section
    # 
    # Returns None, if the data was invalid for a TLS payload type
    #
    def identify_tls_payload_type(self, packet_section):
        
        ## Note, the record header should be at the very begining of the sections
        result = {}
        
        # Data sanity check
        if packet_section == None:
            print("null packet")
            return None
            
        if len(packet_section) < 6:
            #print("Too small packet")
            return None
        
        # Quick bail out if not a supported TLS type, (all start with '1')
        if packet_section[0] != '1':
            return None
            
        ## Check the protocol version
        if packet_section[2:5] != '030':
            # Invalid TLS protocol number
            return None
        
        # TLS 1.0 (wow old). See it sometimes in the initial client hello
        if packet_section[5] == '1':
            result['tls_version'] = '1.0'
        # TLS 1.1 (still old)
        elif packet_section[5] == '2':
            result['tls_version'] = '1.1'
        # TLS 1.2 (currently all that is supported for this tool)
        elif packet_section[5] == '3':
            result['tls_version'] = '1.2'
        # TLS 1.3
        elif packet_section[5] == '4':
            result['tls_version'] = '1.3'
        # Unsupported TLS type
        else:
            print("invalid TLS protocol number, (version)")
            return None
        
        # Default value, should be overridden by each section as I add the parsing
        # for it
        result['next_section'] = 6
        
        ## Check section type
        
        # Change cipher spec
        if packet_section[1] == '4':
            result['type'] = 14
            
        # Alert record
        elif packet_section[1] == '5':
            result['type'] = 15
        
        # If a hello handshake (starts with '16')
        elif packet_section[1] == '6':
            result['type'] = 16
            
            result['next_section'] += int(packet_section[6:10], 16)
            
            ## Get the handshake type
            if packet_section[10:12] == "01":
                result['sub_type'] = "client_hello"
           
            elif packet_section[10:12] == "02":
                result['sub_type'] = "server_hello"
                
                # Advance through the packet:
                cur_section = packet_section[22:]
                
                # Server random number. Starts with timestamp sometimes
                # not currently using this
                server_random = cur_section[:64]
                cur_section = cur_section[64:]
                
                # Session id for restarting sessions
                # not currently using this
                session_id_len = int(cur_section[0:2],16)
                session_id = cur_section[2:2+session_id_len * 2]
                
                # Grab the cipher suite selection which is what this application
                # really cares about
                cur_section = cur_section[2+ (session_id_len * 2):]
                cipher_suite = cur_section[0:4]
                result['cipher'] = cipher_suite
                
                # Grab the compression method which will also be important for
                # doing traffic analysis
                compression_method = cur_section[4:6]
                result['compression'] = compression_method
    
            elif packet_section[10:12] == "0b":
                result['sub_type'] = "server_certificate"
                
            elif packet_section[10:12] == "0e":
                result['sub_type'] = "server_hello_done"
            
            else:
                # print("Don't know what type of hello packet this is")
                # print( packet_section[10:12])
                return None
                
        # If application data section (starts with '17')
        elif packet_section[1] == '7':
            result['type'] = 17
            result['next_section'] += int(packet_section[6:10], 16)
            
            ## Find out how much application data is being sent
            result['size'] = int(packet_section[6:10],16)
                  
        # Unsupported type
        else:
            print("Unsupported type")
            print(packet_section[0:5])
            return None
        
        return result
            