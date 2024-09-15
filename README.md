# Pynternet Sniffer
[!](pylint.svg)

Pynternet Sniffer is a Python script that monitors network activity, logs the activities, and retrieves IP, MAC, and creator information using the ARP protocol.

## Features

- Monitors network connections and logs established connections.
- Retrieves IP and MAC addresses using ARP requests for IPv4 and ICMPv6 for IPv6.
- Logs network activity to a timestamped log file.
- Optionally logs network activity to the terminal.
- Gracefully exits on pressing 'q' or 'Esc'.
- Validates IP addresses before processing.
- Logs only the first request of each MAC address if specified.

## Requirements

- Python 3.x
- `psutil` library
- `scapy` library

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
    sudo python3 main.py
    ```

2. **Generate network activity** (e.g., using `ping`):
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

- **Combine options**:
    ```sh
    sudo python3 main.py -t -m
    ```

## Example

```sh
sudo python3 main.py -t
```

In another terminal:

```sh
ping -c 4 google.com
```

Check the `network_activity<timestamp>.log` file for logged network activity

### License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.