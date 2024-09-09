# Pynternet Sniffer

Pynternet Sniffer is a Python script that monitors network activity, logs the activities, and retrieves IP, MAC, and creator information using the ARP protocol.

## Features

- Monitors network connections and logs established connections.
- Retrieves IP and MAC addresses using ARP requests.
- Logs network activity to a file.
- Gracefully exits on pressing 'q' or 'Esc'.

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
    The network activity will be logged in `network_activity.log`.

4. **Exit the script**:
    Press 'q' or 'Esc' to gracefully exit the script.

## Example

```sh
sudo python3 main.py
```

In another terminal:

```sh
ping -c 4 google.com
```

Check the [`network_activity.log`] file for logged network activity.

## License

This project is licensed under the MIT License. See the LICENSE file for details.