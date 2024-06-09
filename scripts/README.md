# Distributed Security Monitoring System
### Author: Abie Safdie
### Date: 6/3/2024

# Overview
This project is a distributed security monitoring system designed to monitor the security risk of Border Gateway Protocol (BGP) announcements. The system uses a network of BGP Collectors to gather BGP update data, analyze trust levels of BGP peers, and identify suspicious activities based on the trust metrics.

The System uses a federated learning architecture to train models to detect the security threat of BGP announcements.

Please read my attached Project Report for a full description and analysis of this system.


# Prerequisites
### Python 3.x+
### Libraries: requests, math, matplotlib, threading, sys

# Installation
### Ensure you have Python 3.x installed.
# Install required libraries:
* ```pip install requests matplotlib``` 

### Usage
To run the simulation and monitor BGP updates, execute the distributed_security_monitoring script.
* ```python3 distributed_security_monitoring.py```

You will be prompted to enter the name of the site and its IP address. 

Below is an example of a site and IP address to use the program for:

    Enter name of site you intend to use: chess.com 
    Enter the IP of site: 104.17.237.85

Upon these inputs, the program will execute. After conclusion of the program, the final BGP peer trust data will be saved to the local directory. There will be two graphs showing trust values, and a *.txt file stating the final trust value of each peer.

If the database for BGP announcements used (RIPE) does not connect for the specified IP, an error message will be displayed to standard out.