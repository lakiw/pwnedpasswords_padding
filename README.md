# Pwned Passwords API Padding Research
Research into the lack of padding for responses in pwned passwords

## Threat Vector
#### Basic Overview
The Pwned Passwords API allows users to submit a 20 bits of their password hash to an online service, and the API will reply with all password hashes that match those 20 bits. While this transaction is encrypted using TLS, the size of the responses are not uniform. This may allow an attacker utilizing a passive network monitor to determine 20 bits of a password hash by monitoring the size of the response.

#### Worst Case Impact
If an attacker discovers the first 20 bits of a password hash, that would narrow the keyspace they would need to search by around a factor of a million (2^20) if they attempt to compromise an account that utilizes that password.

The main concern is that this could be carried out by a nation level threat actor. This represents an adversary who would be able to passively monitor all queries to the Pwned Passwords API, match up requests/IP addresses with individual users, and would have an interest in carrying out multi-dimensional attacks against high value targets. 

A lesser concern is that this type of attack could also be weaponized and included in more standard offensive network sniffers such as dsniff. 

#### Mitigating Impact Factors
- The Pwned Passwords API calls do not include the username of the user submitting the request, or the account the lookup is associated with.  This info would need to be learned by an attacker via another method.
- Just because a user submits a password as part of a query does not mean they are currently using that password for any active account.
- While 20 bits of a password hash would reduce the keyspace significantly, an attacker would still likely have to deal with a high number of collisions when attempting to guess the plaintext password the user selected. To put things in context, against fast password hashes, attackers usually generate billions of guesses a second, which would correlate to around 1 thousand hits/false positive matches a second.

#### Current Threat Assessment
- Regardless of the exploitability of the information, giving an attacker 20 bits of your password hash is not a situation that I would be comfortable with.
- If this vulnerability is exploitable, it would be a ****passive vulnerability****. This means all an attacker needs to do is sniff a connection. They do not need to break TLS encryption, or more actively run a person in the middle attack. An attacker could also go through old packet captures and extract the partial hashes if they later learned how to weaponize this attack.
- The situations where this information would be most exploitable would be when a targeted user account is expensive to make guesses against. This could be an online attack against a service that enforces rate limiting, or if the attacker is trying to crack a very computationally expensive password hash such as those used in many hard drive encryption programs. In these cases, having 20 bits of a password hash belonging to the targeted user would allow an attacker to significantly optimize their attacks.

#### Suggested Fix/Patch/Solution
- The standard cryptographic solution to a problem like this would be to add padding to all of the responses from the Pwned Passwords API so they all are the same length. 
- In practice, there would likely be a number of complications with implementing padding, such as dealing with TLS compression, backwards compatibility with tools built on the current API, and the fact that the database of compromised passwords the API pulls from is being updated as new leaks become available.
- While other approaches could be taken as well to minimize the risk, ultimately padding all the results to be the same length should be the ideal end goal.

## Research Question
The open question this investigation is seeking to answer is if the different sized responses of the Pwned Passwords API could be weaponized by an attacker, or if standard TCP/TLS artifacts, encodings, and encryption add enough noise to make this vulnerability impractical to exploit.

## Tools Included In this Repo
1. query_pwned_passwords.py: Creates requests to the Pwned Passwords API
    - By default it will start by querying the hash prefix 00000 and increment it by one until it queries the final hash prefix fffff
    - It will output the hash prefix, the html status code, and the size of the plaintext response. By default it will print these to stdout, though you can also tell it to save the results to a file.
    - You can also give it one single hash prefix, and it will repeatedly query it. This is useful for testing the sniffer's ability to identify a hash prefix by analyzing an encrypted connection.
2. trainer.py: Creates a training ruleset that associates a Pwned Passwords API call with the size of the encrypted responses.
3. sniffer.py: Sniffs for pwned passwords lookups and attempts to select the potential hash prefixes by analyzing the size of the responses.

## Current limitations of the Proof of Concept Attack/Toolset
- A real attack would need a full featured TLS parser that could handle multiple different cipher suite selections, as well as the underlying TCP protocol details such as packet fragmentation, packet loss/retransmission, different windowing sizes, etc. I could not find a TLS parser that I could integrate with my PoC code, (Scapy does not handle TLS by default, and I ran into tons of issues trying to leverage PyShark). What I'm trying to say is the current PoC uses a bunch of hacked up shortcuts that have a tendency to fail horribly. Any real attack would likely require a complete rewrite of the code and the above mentioned full featured TLS parser 
- Only trained/tested against TLS 1.2 connections using the Python3 requests library. Therefore the current PoC attack would likely not work against most real world queries to the pwned passwords API using standard web browsers.
- TLS 1.3 introduces several new cipher options that add random padding into connections. This would make an attack against the Pwned Passwords API much more challenging to implement. Research into the actual impact of random padding in TLS 1.3 is currently beyond the scope of this research effort.
- The training of the current PoC is slow and error prone. A different approach would likely need to be taken to advance this work beyond a basic PoC.
- As mentioned earlier, many shortcuts were taken when parsing the TLS sessions. No sanity checks are put in place for parsing TLS so if a record says a data field is X bytes long but it is spread across multiple TCP packets the parser will crash. Also sessions that contain fragmentation, or multiple resent packets are discarded.  Long story short, the TLS analyzer is a hot mess and fails more often then it succeeds.
- Once again, this code is buggy, and prone to crash or produce incorrect results depending on how TCP/TLS is formatting the messages. It is miles away from a real attack.

## Usage

#### Required Tools/Libraries
- Python3
- Python3 library: scapy
- Python3 library: requests

#### Training
Basic option: run trainer.py

`python3 trainer.py -f training_file.txt`

Note: Trainer.py takes a minute to start up, even when only using the help flag, since it needs to load the scapy module to perform packet sniffing.

Note 2: You can append to an existing training session by specifying the hash prefix to start training from. This is useful if you need to restart a previous training session.

`python3 trainer.py -f training_file.txt -s START_HASH_PREFIX`

More advanced features, (such as specifying the network interface to train on), can be found in the help options of trainer.py

#### Testing PoC / Sniffing Pwned Password Lookups
Currently the Proof of Concept is set up to be run using two different programs. One program makes queries the Pwned Password API using the Python3 requests library. The second program sniffs the wire using Scapy and attempts to identify Pwned Passwords queries and then guess what hash prefix was submitted based on the size of the response.

To repeatedly query the Pwned Passwords API:

`python3 query_pwned_passwords.py -s HASH_PREFIX_TO_QUERY`

To run the sniffer:

`python3 sniffer.py -f training_file.txt`

The training file is the one that was previously created during the training stage. When the sniffer is run, it'll keep on sniffing the wire until it detects a pwned password lookup. It listens for a bit afterwards to try and ensure it collects the full session, so multiple pwned passwords lookups may be detected and categorized in this timeframe, especially if you are using the query tool.

## Findings to Date:
From a basic Proof of Concept standpoint, the attack seems feasible.
- Results of analyzing the different sized results of the plaintext results can be seen in the included pwned_passwords_plaintext.txt. These were collected using the query_pwned_passwords.py tool. They show a significant variation in size between the different hash prefix queries.
- Trained the sniffer on over 172 TLS encrypted hash prefix queries.
- The sniffer is able to differentiate between them from passive TLS sniffing ... when the sniffer is working. 
- The sniffer, (and for that matter the trainer), will frequently stop working and basically record the size of the TLS sessions as garbage. This is almost certainly related to how poorly the TLS parser is currently written. Basically it seems like when I have a "good/reliable" internet connection it works ok, but the second the connection gets weird all my parsing goes out the window.
- There's enough positive results to date that the attack looks feasible if the attacker has someone working for them that really understands TLS parsing, or already has libraries to do traffic analysis.
