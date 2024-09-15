#!/bin/bash

# File containing the IP addresses
input_file="dump/remote_ip.txt"
output_file="dump/remote-info.txt"

# Create or clear the output file
> "$output_file"

# Read each line (IP address) from the input file
while IFS= read -r ip; do
  echo "Information for IP: $ip" >> "$output_file"
  whois "$ip" >> "$output_file"
  echo "----------------------------------------" >> "$output_file"
done < "$input_file"