## Table of Contents

1. [Introduction](#introduction)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Usage](#usage)
   - [Running the Simulation](#running-the-simulation)
   - [Understanding the Output](#understanding-the-output)
5. [Classes and Methods](#classes-and-methods)
   - [BGPPeer Class](#bgppeer-class)
   - [BGPCollector Class](#bgpcollector-class)
6. [Functions](#functions)
7. [Troubleshooting](#troubleshooting)
8. [Contact Information](#contact-information)

## Introduction

The Distributed Security Monitoring System is designed to monitor and analyze BGP announcements. This system uses a distributed approach with multiple BGP collectors working in parallel to gather data, compute trust levels for BGP peers, and identify suspicious activities.
The system uses the RIPE database for BGP data.

## System Requirements

- Python 3.x
- Required Python libraries: `requests`, `math`, `matplotlib`, `threading`, `sys`

## Installation

1. Ensure Python 3.x is installed on your system.
2. Install the required libraries by running the following command:

    ```bash
    pip install requests matplotlib
    ```

## Usage

### Running the Simulation

1. Open a terminal or command prompt.
2. Navigate to the directory containing the distributed_security_monitoring script (`distributed_security_monitoring.py`).
3. Run the script using the following command:

    ```bash
    python3 distributed_security_monitoring.py
    ```

4. You will be prompted to enter the name of the site and its IP address:

    ```plaintext
    Enter name of site you intend to use: chess.com
    Enter the IP of site: 104.17.237.85
    ```

5. The simulation will run, which may take a few minutes as it processes several months of BGP data.

### Understanding the Output

The system generates the following files in the current directory:

- **Line Graph**: A graph showing the trust values of BGP peers over time (`{name-of-site}-line-graph.png`).
- **Bar Graph**: A graph showing the final trust values of BGP peers (`{name-of-site}-bar-graph.png`).
- **Text File**: A file listing the final trust values of each BGP peer (`{name-of-site}.txt`).

## Classes and Methods

### BGPPeer Class

**Description**: Represents a BGP peer with its IP address, trust level.

**Methods**:
- `__init__(self, ip)`: Initializes a BGP peer with a specified IP and sets the default trust level to 100.
- `update_trust(self, trust_vals)`: Updates the peer's trust level based on the provided trust values.

### BGPCollector Class

**Description**: Represents a BGP collector responsible for gathering and analyzing BGP update data.

**Methods**:
- `__init__(self, ip_prefix, collector, starttime, endtime)`: Initializes a collector with specified parameters.
- `count_occurrences(self, dictionary, values, keys_are_list=False)`: Updates a dictionary with the frequency of given values.
- `update_peers(self, peer_ip, trust_values=None)`: Updates the trust of a BGP peer or adds a new peer.
- `flag_path(self, peer, val)`: Flags potential BGP hijacking incidents.
- `collect_initial_data(self)`: Collects initial BGP update data and trains models.
- `train_models(self)`: Trains models for path lengths, paths, and communities.
- `calculate_ratios(self, path_length, path, community)`: Calculates trust ratios for path length, path, and community.
- `receive_update(self, start, end)`: Receives and processes BGP updates.
- `send_local_models(self, path_length, path, community)`: Sends local models to the leader.
- `elect_leader(self)`: Elects a new leader among the collectors.
- `update_models(self, path_length, path_model, community_model)`: Updates models with data from other collectors.
- `receive_central_model(self, path_length_model, path_model, community_model)`: Updates local models with the central model.

## Functions

- `save_trust_for_graph()`: Saves trust values for graph plotting.
- `plot_line_graph(name)`: Plots and saves a line graph of trust values over time.
- `plot_bar_graph(name)`: Plots and saves a bar graph of final trust values.
- `update(bgp_collector: BGPCollector, start, end)`: Function that threads call to start the updates for
