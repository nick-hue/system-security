#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"
adblockRulesIPv6="adblockRulesIPv6"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Configure adblock rules based on the domain names of $domainNames file.
        echo "Configuring adblock rules for Domain Names."
        truncate -s 0 $IPAddresses # clearing IPaddresses file from previous runs

        while read -r domain; do 
            host "$domain" | awk '/has (IPv6 )?address/ {print $NF}' | while read -r address; do
            
                echo $address >> $IPAddresses            
                # Check if the address contains a colon, indicating it's IPv6
                if [[ $address == *:* ]]; then
                    sudo ip6tables -A INPUT -s "$address" -j REJECT
                    sudo ip6tables -A OUTPUT -s "$address" -j REJECT
                else
                    sudo iptables -A INPUT -s "$address" -j REJECT
                    sudo iptables -A OUTPUT -s "$address" -j REJECT 
                fi

            done
        done < $domainNames
        true
            
    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        echo "Configuring adblock rules for IP addresses."
        while read -r address
        do  
            if [[ "$address" == *:* ]]; then
                sudo ip6tables -A INPUT -s "$address" -j REJECT
                sudo ip6tables -A OUTPUT -s "$address" -j REJECT
            else
                sudo iptables -A INPUT -s "$address" -j REJECT
                sudo iptables -A OUTPUT -s "$address" -j REJECT 
            fi 

        done < $IPAddresses
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        sudo iptables-save > $adblockRules
        sudo ip6tables-save > $adblockRulesIPv6
        echo "Rules saved."
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        sudo iptables-restore < $adblockRules
        sudo ip6tables-restore < $adblockRulesIPv6
        echo "Rules loaded."
        true
        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        echo "Reseting rules to default settings (i.e. accept all)"
        sudo iptables -F
        sudo ip6tables -F
        true

    elif [ "$1" = "-list"  ]; then
        # List current rules.
        echo "--- ipv4 rules: "
        sudo iptables -L -v -n
        echo "--- ipv6 rules: "
        sudo ip6tables -L -v -n
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0