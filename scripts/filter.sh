#!/bin/bash

# List all network_activity log files with numbers
echo "Available network activity log files:"
files=($(ls network_activity_*.log))
for i in "${!files[@]}"; do
  echo "$i) ${files[$i]}"
done

# Prompt the user to select a file by number
read -p "Please enter the number of the log file you want to process: " file_number

# Check if the entered number is valid
if [[ ! "$file_number" =~ ^[0-9]+$ ]] || [[ "$file_number" -ge "${#files[@]}" ]]; then
  echo "Invalid selection!"
  exit 1
fi

# Get the selected file
LOG_FILE="${files[$file_number]}"

# Check if the file exists (redundant check, but kept for safety)
if [[ ! -f "$LOG_FILE" ]]; then
  echo "File not found!"
  exit 1
fi

# Create dump directory if it doesn't exist
mkdir -p dump

# Extract unique Local IP and Local MAC addresses
grep -oP 'Local IP: \K[^,]+, Local MAC: [^,]+' "$LOG_FILE" | sort | uniq > dump/local_ip_mac.txt

# Extract unique Remote IP addresses
grep -oP 'Remote IP: \K[^,]+' "$LOG_FILE" | sort | uniq > dump/remote_ip.txt

echo "Extraction complete. Check dump/local_ip_mac.txt and dump/remote_ip.txt for results."