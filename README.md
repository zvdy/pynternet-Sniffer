# Pynternet Sniffer

![pylint](pylint.svg) ![py-ver](https://img.shields.io/badge/Python-3.12-blue)  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pynternet Sniffer is a Python script that monitors network activity, logs the activities, and retrieves IP, MAC, and creator information using the ARP protocol.

## Features

- Monitors network connections and logs established connections.
- Retrieves IP and MAC addresses using ARP requests for IPv4 and ICMPv6 for IPv6.
- Logs network activity to a timestamped log file.
- Optionally logs network activity to the terminal.
- Gracefully exits on pressing 'q' or 'Esc'.
- Validates IP addresses before processing.
- Logs only the first request of each MAC address if specified.
- Scans the local network for devices within a specified IP range.
- Adds MAC manufacturer information to log entries.

## Requirements

- Python 3.x
- [`psutil`] library
- [`scapy`] library

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/zvdy/pynternet-sniffer.git
    cd pynternet-sniffer
    ```

2. **Create a virtual environment** (optional but recommended):
    ```sh
    python -m venv venv
    source venv/bin/activate
    ```

3. **Install the required libraries**:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. **Run the script with elevated privileges**:
    ```sh
    sudo /venv/bin/python main.py

    # or

    sudo python main.py
    ```

2. **Generate network activity** (e.g., using [`ping`]):
    ```sh
    ping -c 4 google.com
    ```

3. **Check the log file**:
    The network activity will be logged in a file named `network_activity_<timestamp>.log`.

4. **Exit the script**:
    Press 'q' or 'Esc' to gracefully exit the script.

### Additional Options

- **Log activity to the terminal**:
    ```sh
    sudo python3 main.py -t
    ```

- **Log only the first request of each MAC address**:
    ```sh
    sudo python3 main.py -m
    ```

- **Specify IP range to scan for devices**:
    ```sh
    sudo python3 main.py -r 192.168.1.1/24
    ```

- **Combine options**:
    ```sh
    sudo python3 main.py -t -m -r 192.168.1.1/24
    ```

## Example

```sh
sudo python3 main.py -t
```

In another terminal:

```sh
ping -c 4 google.com
```

Check the `network_activity<timestamp>.log` file for logged network activity.

## Additional Scripts

### `who.sh`

The `who.sh` script processes a list of IP addresses from an input file and retrieves information about each IP using the `whois` command. The results are saved to an output file.

#### Usage

1. **Ensure the input file [`dump/remote_ip.txt`] exists**:
    This file should contain a list of IP addresses, one per line.

2. **Run the script**:
    ```sh
    ./scripts/who.sh
    ```

3. **Check the output file**:
    The information for each IP will be saved in [`dump/remote-info.txt`].

### `filter.sh`

The `filter.sh` script lists available network activity log files, prompts the user to select one, and then extracts unique local IP/MAC addresses and remote IP addresses from the selected log file. The results are saved in separate files.

#### Usage

1. **Run the script**:
    ```sh
    ./scripts/filter.sh
    ```

2. **Follow the prompts**:
    Select the log file you want to process from the list.

3. **Check the output files**:
    - [`dump/local_ip_mac.txt`] will contain unique local IP and MAC addresses.
    - [`dump/remote_ip.txt`] will contain unique remote IP addresses.

## License
This project is licensed under the MIT License. See the [`LICENSE`] file for details.