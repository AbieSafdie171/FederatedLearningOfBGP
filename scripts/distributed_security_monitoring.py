import requests
import datetime
import numpy as np
from sklearn.ensemble import IsolationForest


class BGPCollector:

    def __init__(self, ip_prefix, collector):
        self.ip_prefix = ip_prefix
        self.collector = collector
        self.raw_announcement_data = []
        self.raw_freq_data = []
        self.raw_withdrawal_data = []

    def collect_data(self, starttime=None):

        update_url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
                     f"&rrcs={self.collector}&starttime=2024-04-01T17:59:51"

        update_response = requests.get(update_url)
        bgp_updates = None

        if update_response.status_code == 200:
            update_data = update_response.json()
            nr_updates = update_data["data"]["nr_updates"]
            bgp_updates = update_data["data"]["updates"]
            self.raw_freq_data.append(nr_updates)
            path_lengths = []
            for update in bgp_updates:
                type_of_update = update["type"]
                if type_of_update == "A":
                    path_length = len(update["attrs"]["path"])
                    path = update["attrs"]["path"]
                    source_id = update["attrs"]["source_id"]
                    source_id = source_id.replace(f"{self.collector}-",
                                                  "")
                    target_prefix = update["attrs"]["target_prefix"]
                    community = update["attrs"]["community"]
                    path_lengths.append(path_length)
                    self.raw_announcement_data.append(
                        [path, source_id, target_prefix, community])
                else:
                    source_id = update["attrs"]["source_id"]
                    source_id = source_id.replace(f"{self.collector}-",
                                                  "")
                    target_prefix = update["attrs"]["target_prefix"]

                    self.raw_withdrawal_data.append([source_id, target_prefix])
            self.raw_freq_data.append(path_lengths)

    def print_raw_data(self, data=None):
        if data == "A":
            print(self.raw_announcement_data)
        elif data == "W":
            print(self.raw_withdrawal_data)
        else:
            print(self.raw_freq_data)

    def train_model(self):
        pass


class BGPCentral:
    pass


if __name__ == "__main__":
    bgp_collector_11 = BGPCollector("159.121.0.0/16", "11")
    bgp_collector_11.collect_data()

    bgp_collector_12 = BGPCollector("159.121.0.0/16", "12")
    bgp_collector_12.collect_data()

    bgp_collector_14 = BGPCollector("159.121.0.0/16", "14")
    bgp_collector_14.collect_data()
