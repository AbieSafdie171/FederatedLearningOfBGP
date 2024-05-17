import requests  # to connect to ripe database
import math
import matplotlib.pyplot as plt
import threading  # to run multiple collectors in parallel

leader = None
collectors = None
mutex = threading.Lock()

def ip_to_integer(ip_address):
    octets = ip_address.split('.')

    binary_ip = ''
    for octet in octets:
        binary_octet = bin(int(octet))[2:].zfill(8)
        binary_ip += binary_octet

    return int(binary_ip, 2)


class BGPCollector:

    def __init__(self, ip_prefix, collector, starttime, endtime):
        self.trust = 1000
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
        self.path_length_ratio = None
        self.ip_ratio = None
        self.path_ratio = None
        self.comm_ratio = None
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

    def collect_initial_data(self):

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
            self.train_models()
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
        self.path_length_ratio = path_length_value / path_length_sum
        path_length_trust = self.path_length_ratio

        """IPs"""
        ip_value = 0
        ip_sum = 0
        for key, value in self.ip_model.items():
            ip_sum += value
            if key == ip:
                ip_value = value
        self.ip_ratio = ip_value / ip_sum
        ip_trust = self.ip_ratio

        """Path"""
        path_value = 0
        path_sum = 0
        for key, value in self.path_model.items():
            path_sum += value
            if key == tuple(path):
                path_value = value
        self.path_ratio = path_value / path_sum
        path_trust = self.path_ratio

        """Community"""
        comm_value = 0
        comm_sum = 0
        for key, value in self.community_model.items():
            comm_sum += value
            if key == tuple(community):
                comm_value = value
        self.comm_ratio = comm_value / comm_sum
        comm_trust = self.comm_ratio

        return [path_length_trust, ip_trust, path_trust, comm_trust]

    def receive_update(self, start, end):
        update_url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
                     f"&rrcs={self.collector}&starttime={start}&endtime={end}"
        print("Update received")
        with mutex:
            update_response = requests.get(update_url)
            bgp_updates = None
            global leader
            print(threading.current_thread().ident, "got the lock")
            if update_response.status_code == 200:
                update_data = update_response.json()
                self.nr_updates += update_data["data"]["nr_updates"]
                bgp_updates = update_data["data"]["updates"]
                self.raw_path_lengths = []
                self.raw_source_ips = []
                self.raw_paths = []
                self.raw_community = []
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
                        self.raw_source_ips.append(source_id)
                        self.raw_community.append(community)

                        trust_vals = self.calculate_ratios(path_length, source_id, path, community)
                        print(trust_vals)


                self.train_models()
                #if self is not leader:
                    #self.send_local_models(self.raw_path_lengths, self.raw_paths, self.raw_source_ips, self.raw_community)
                # self.update_trust(trust_vals)

    def update_trust(self, trust_vals):
        path_length = trust_vals[0]
        source_id = trust_vals[1]
        path = trust_vals[2]
        community = trust_vals[3]

        # delta_trust = path_length
        k = 1
        d = 1
        delta_path_length = (1 - math.exp(
            -k * abs(2 * path_length - 1))) * math.copysign(1,
                                                            2 * path_length - 1) * d

        # print(path_length, "|", delta_path_length)

        k = 1
        d = 1
        delta_source_id = (1 - math.exp(
            -k * abs(2 * source_id - 1))) * math.copysign(1,
                                                          2 * source_id - 1) * d
        # print(source_id, "|", delta_source_id)

        k = 2
        d = 5
        delta_path = (1 - math.exp(-k * abs(2 * path - 1))) * math.copysign(1,
                                                                            2 * path - 1) * d
        # print(path, "|", delta_path)

        k = 2
        d = 2
        delta_community = (1 - math.exp(
            -k * abs(2 * community - 1))) * math.copysign(1,
                                                          2 * community - 1) * d
        # print(community, "|", delta_community)

        self.trust += delta_path + delta_community + delta_source_id + delta_path_length

        # use threads and mutal exclusion and share data updates and oh my oh lord oh no

        # send trust update

    def send_local_models(self, path_length, source_id, path, community):
        """
            Sending my Model
        """
        # print("hello")
        global leader
        leader.update_models(path_length, source_id,
                             path, community)

    def update_models(self, path_length_model, ip_model, path_model,
                      community_model):
        """
            Update Models
        """
        # print(path_length_model)
        for value in path_length_model:
            if value in self.path_length_model:
                self.path_length_model[value] += 1
            else:
                self.path_length_model[value] = 1


        global leader
        global collectors
        if self is leader:
            for collector in collectors:
                if collector is not self:
                    collector.receive_central_model(self.path_length_model,
                                                    self.ip_model,
                                                    self.path_model,
                                                    self.community_model)

    def receive_central_model(self, path_length_model, ip_model, path_model,
                              community_model):
        self.path_length_model = path_length_model
        self.ip_model = ip_model
        self.path_model = path_model
        self.community_model = community_model


def update(bgp_collector: BGPCollector, start, end):
    bgp_collector.receive_update(start, end)
    print(f"{bgp_collector.collector}: {bgp_collector.trust}")


if __name__ == "__main__":
    # 140.211.0.0/16 = ?
    # 159.121.0.0/16 = ?
    # 208.65.153.238 = youtube

    startime = "2024-02-01T17:59:51"
    endtime = "2024-04-01T17:59:51"
    bgp_collector_11 = BGPCollector("208.65.153.238", "11", startime, endtime)
    bgp_collector_14 = BGPCollector("208.65.153.238", "14", startime, endtime)
    bgp_collector_16 = BGPCollector("208.65.153.238", "16", startime, endtime)


    stime = "2024-05-11T17:59:51"
    etime = "2024-05-15T17:59:51"

    collectors = [bgp_collector_11, bgp_collector_14, bgp_collector_16]
    collector_threads = []

    for collector in collectors:
        collector.collect_initial_data()

    leader = collectors[0]

    for collector in collectors:
        worker = threading.Thread(target=update, args=(collector, stime, etime))
        collector_threads.append(worker)
        worker.start()

    for worker in collector_threads:
        worker.join()

    for collector in collectors:
        print(collector.path_length_model)
