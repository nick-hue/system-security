ΗΡΥ 413 Assignment: 5
AM: 2019030190 Nikolaos Angelidis  
AM: 2019030201 Chrysiis Manoudaki

In order to run our program: 
$sudo ./adblock.sh <option>

Options: 

1. -domains
- In order to get the ip addresses from a certain domain we use a series of commands that writes the current IP address that got parsed from the response (awk) of the DNS query (host) and then set the rules for the specific IP address with the iptables and the ip6tables command. 

2. -ips
- We set the rules for every IP address generated in the previous feature with the help of the iptables and the ip6tables command.

3. -save
- We save into the adblockRules file the rules that have been generated from the -domain or -ips option.

4. -load
- We load from the adblockRules file the rules that have been saved from a previous session into our current session.

5. -list
- We show all the current rules applied.

6. -reset
- We reset all the current rules applied.

7. -help
- Displays help message.

Questions
1. After configuring the adblock rules, test your script by visiting your favorite
websites without any other adblocking mechanism (e.g., adblock browser
extensions). Can you see ads? Do they load? Some ads persist, why?

Most ads are not visible on most websites because they are got rejected. Although, some ads persist because some websites employ dynamic loading techniques to fetch ads after the initial page load. Also, some websites often implement anti-adblock measures to detect and counteract adblockers.