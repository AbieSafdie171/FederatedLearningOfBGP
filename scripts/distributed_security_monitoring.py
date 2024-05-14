import requests
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd


def ip_to_integer(ip_address):
    octets = ip_address.split('.')

    binary_ip = ''
    for octet in octets:
        binary_octet = bin(int(octet))[2:].zfill(8)
        binary_ip += binary_octet

    return int(binary_ip, 2)


class BGPCollector:

    def __init__(self, ip_prefix, collector, starttime, endtime):
        self.ip_prefix = ip_prefix
        self.collector = collector
        self.starttime = starttime
        self.endtime = endtime
        self.nr_updates = None
        self.raw_paths = []
        self.raw_path_lengths = []
        self.raw_community = []
        self.raw_source_ips = []
        self.raw_withdrawal_ips = []
        self.path_length_model = {}
        self.ip_model = {}
        self.path_model = {}
        self.community_model = {}
        self.withdrawal_ip_model = {}

    def count_occurrences(self, dictionary, values, keys_are_list=False):
        for value in values:
            if keys_are_list:
                value = tuple(value)
            if value in dictionary:
                dictionary[value] += 1
            else:
                dictionary[value] = 1
        return None

    def collect_data(self):

        update_url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
                     f"&rrcs={self.collector}&starttime={self.starttime}&endtime={self.endtime}"

        update_response = requests.get(update_url)
        bgp_updates = None

        if update_response.status_code == 200:
            update_data = update_response.json()
            self.nr_updates = update_data["data"]["nr_updates"]
            bgp_updates = update_data["data"]["updates"]
            for update in bgp_updates:
                type_of_update = update["type"]
                if type_of_update == "A":
                    path_length = len(update["attrs"]["path"])
                    path = update["attrs"]["path"]
                    source_id = update["attrs"]["source_id"]
                    source_id = source_id.replace(f"{self.collector}-",
                                                  "")
                    source_id = ip_to_integer(source_id)
                    community = update["attrs"]["community"]

                    self.raw_path_lengths.append(path_length)
                    self.raw_paths.append(path)
                    self.raw_community.append(community)
                    self.raw_source_ips.append(source_id)

                else:
                    source_id = update["attrs"]["source_id"]
                    source_id = source_id.replace(f"{self.collector}-",
                                                  "")
                    source_id = ip_to_integer(source_id)
                    self.raw_withdrawal_ips.append(source_id)
        else:
            print("error connecting to ripe database")

    def train_models(self):
        self.train_path_lengths()
        self.train_ip()
        self.train_paths()
        self.train_community()
        self.train_withdrawal_ips()

    def train_path_lengths(self):
        self.count_occurrences(self.path_length_model, self.raw_path_lengths)

    def train_ip(self):
        self.count_occurrences(self.ip_model, self.raw_source_ips)

    def train_paths(self):
        self.count_occurrences(self.path_model, self.raw_paths, True)

    def train_community(self):
        self.count_occurrences(self.community_model, self.raw_community, True)

    def train_withdrawal_ips(self):
        self.count_occurrences(self.withdrawal_ip_model,
                               self.raw_withdrawal_ips)

    def calculate_ratios(self, path_length, ip, path, community):
        """
            Docstring
        """

        """Path Lengths"""
        path_length_value = 0
        path_length_sum = 0
        for key, value in self.path_length_model.items():
            path_length_sum += value
            if key == path_length:
                path_length_value = value
        path_length_ratio = path_length_value / path_length_sum
        print(path_length_ratio)

        """IPs"""
        ip_value = 0
        ip_sum = 0
        for key, value in self.ip_model.items():
            ip_sum += value
            if key == ip:
                ip_value = value
        ip_ratio = ip_value / ip_sum
        print(ip_ratio)

        """Path"""
        path_value = 0
        path_sum = 0
        for key, value in self.path_model.items():
            path_sum += value
            if key == tuple(path):
                path_value = value
        path_ratio = path_value / path_sum
        print(path_ratio)

        """Community"""
        comm_value = 0
        comm_sum = 0
        for key, value in self.community_model.items():
            comm_sum += value
            if key == tuple(community):
                comm_value = value
        comm_ratio = comm_value / comm_sum
        print(comm_ratio)

    def receive_update(self, start, end):
        update_url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
                     f"&rrcs={self.collector}&starttime={start}&endtime={end}"

        update_response = requests.get(update_url)
        bgp_updates = None

        if update_response.status_code == 200:
            update_data = update_response.json()
            self.nr_updates += update_data["data"]["nr_updates"]
            bgp_updates = update_data["data"]["updates"]
            for update in bgp_updates:
                type_of_update = update["type"]
                if type_of_update == "A":
                    path_length = len(update["attrs"]["path"])
                    path = update["attrs"]["path"]
                    source_id = update["attrs"]["source_id"]
                    source_id = source_id.replace(f"{self.collector}-",
                                                  "")
                    source_id = ip_to_integer(source_id)
                    community = update["attrs"]["community"]

                    self.raw_path_lengths.append(path_length)
                    self.raw_paths.append(path)
                    self.raw_community.append(community)
                    self.raw_source_ips.append(source_id)

        self.train_models()

    def define_trust(self):
        pass

    def update_trust(self):
        pass

    def receive_trust_update(self):
        pass


if __name__ == "__main__":
    # 140.211.0.0/16 = ?
    # 159.121.0.0/16 = ?
    # 208.65.153.238 = youtube

    startime = "2024-02-01T17:59:51"
    endtime = "2024-04-01T17:59:51"
    bgp_collector_11 = BGPCollector("208.65.153.238", "11", startime, endtime)
    bgp_collector_11.collect_data()
    bgp_collector_11.train_models()

    bgp_collector_11.calculate_ratios(3, 3324026919, [9002, 15169, 43515],
                                      ['13030:1', '13030:3', '13030:50000',
                                       '13030:51129'])

    bgp_collector_11.receive_update("2024-04-02T17:59:51",
                                    "2024-05-01T17:59:51")

    print("---------------------------------")

    bgp_collector_11.calculate_ratios(3, 3324026919, [9002, 15169, 43515],
                                      ['13030:1', '13030:3', '13030:50000',
                                       '13030:51129'])

    """
    startime2 = "2024-04-02T17:59:51"
    endtime2 = "2024-05-012T17:59:51"
    bgp_collector_11_2 = BGPCollector("208.65.153.238", "11", startime2, endtime2)
    bgp_collector_11_2.collect_data()
    bgp_collector_11_2.train_models()
    """

    # Implement a trust model
    """
    bgp_collector_12 = BGPCollector("208.65.153.238", "16")
    bgp_collector_12.collect_data()
    bgp_collector_12.train_models()

    bgp_collector_14 = BGPCollector("208.65.153.238", "14")
    bgp_collector_14.collect_data()
    bgp_collector_14.train_models()
    """
