import requests
import datetime
import numpy as np
from sklearn.ensemble import IsolationForest


class BGPCollector:

    def __init__(self, ip_prefix, collector):
        self.ip_prefix = ip_prefix
        self.collector = collector
        self.raw_announcement_data = []
        self.raw_withdrawal_data = []

    def collect_data(self, starttime=None):

        url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
              f"&rrcs={self.collector}&starttime=2024-04-15T17:59:51"

        response = requests.get(url)
        bgp_updates = None

        if response.status_code == 200:
            data = response.json()
            bgp_updates = data["data"]["updates"]

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
                    self.raw_announcement_data.append([path_length, path, source_id, target_prefix, community])

                else:
                    print(update)
                    source_id = update["attrs"]["source_id"]
                    source_id = source_id.replace(f"{self.collector}-",
                                                  "")
                    target_prefix = update["attrs"]["target_prefix"]

                    self.raw_withdrawal_data.append([source_id, target_prefix])


    def print_raw_data(self, data):
        if data == "A":
            print(self.raw_announcement_data)
        else:
            print(self.raw_withdrawal_data)



class BGPCentral:
    pass


if __name__ == "__main__":
    test = BGPCollector("159.121.0.0/16", "11")
    test.collect_data()
    # test.print_raw_data("W")
