"""
Author: Abie Safdie
Date: 6/3/2024

This file serves as my main driver for my distributed security monitoring system.

See the attached README.md and manual for more information on how to use this system.

"""

import requests  # to connect to ripe database
import math  # math!
import matplotlib.pyplot as plt  # plotting library
import threading  # to run multiple collectors in parallel
import sys

leader = None  # bgp collector who acts as leader
collectors = None  # list of collectors
trust_over_time = {}  # trust values for plotting
mutex = threading.Lock()  # lock for mutual exclusion across threads
ratio_mutex = threading.Lock()
base_trust = 100

peer_lock = threading.Lock()
bgp_peers = []


class BGPPeer:
    """Router Object than originates the BGP Update"""

    def __init__(self, ip):
        """
        Define the IP of the origin and set default trust to 100
        :param ip: ip address
        """
        self.ip = ip
        self.trust = 100
        self.num_updates = 0

    def update_trust(self, trust_vals):
        """
        Apply trust algorithm to update trust based on data
        :param trust_vals: frequencies of given data
        :return: None
        """
        self.num_updates += 1
        delta_trust = 0  # value to add to trust
        k = 0.2
        for i in range(len(trust_vals)):
            # if path attribute and if new announcement (<0.01) apply greater weight
            d = 0.75 if trust_vals[i] <= 0.01 and i == 1 else 0.4
            tmp = (1 - math.exp(
                -k * abs(1.75 * trust_vals[i] - 1))) * math.copysign(1, 1.75 *
                                                                     trust_vals[
                                                                         i] - 1) * d
            delta_trust += tmp

        self.trust += delta_trust  # update trust
        return delta_trust


class BGPCollector:
    """
    BGP Collector (Listener) Object
    """

    def __init__(self, ip_prefix, collector, starttime, endtime):
        """
        :param ip_prefix: ip that we are collecting updates for
        :param collector: collector number
        :param starttime: initial starttime to collect data to use
        :param endtime: initial endtime to collect data to use
        """
        self.collector = collector
        self.ip_prefix = ip_prefix
        self.starttime = starttime
        self.endtime = endtime
        self.nr_updates = None  # number of updates
        self.raw_paths = []  # new update paths get stored here
        self.raw_path_lengths = []  # new path lengths
        self.raw_community = []  # new bgp communities
        self.path_length_ratio = None  # frequency of occurence of new path length to existing
        self.path_ratio = None  # frequency of occurence of new path to existing
        self.comm_ratio = None  # frequency of bgp comm to existing
        self.path_length_model = {}  # dict containing path length mapped to how many times it occured
        self.path_model = {}  # dict containing paths mapped to how many times it occured
        self.community_model = {}  # dict containing bgp communities mapped to how many times it occured

    def count_occurrences(self, dictionary, values, keys_are_list=False):
        """
        :param dictionary: pre-built dictionary containing the key value pairs
                            that will be updated
        :param values: values to put into dict
        :param keys_are_list:   if keys are list, need to convert to tuple
        :return: None
        """
        for value in values:
            if keys_are_list:
                value = tuple(value)
            if value in dictionary:
                dictionary[value] += 1  # increment occurrence
            else:
                dictionary[value] = 1  # set key-value pair
        return None

    def update_peers(self, peer_ip, trust_values=None):
        peer_lock.acquire()
        global bgp_peers
        for peer in bgp_peers:
            if peer.ip == peer_ip:
                if trust_values is not None:
                    val = peer.update_trust(trust_values)
                    self.flag_path(peer, val)
                peer_lock.release()
                return None
        bgp_peers.append(BGPPeer(peer_ip))
        peer_lock.release()
        return None

    def flag_path(self, peer, val):
        if peer.trust < (base_trust * 0.6) and val < 0:
            print(f"POTENTIAL BGP HIJACKING DETECTED FROM {peer.ip}. ALERT "
                  f"SYSTEM ADMIN")

    def collect_initial_data(self):
        """
            Build the initial data tables and models based on the initial data
        :return: None
        """

        # get data from ripe
        update_url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
                     f"&rrcs={self.collector}&starttime={self.starttime}&endtime={self.endtime}"

        update_response = requests.get(update_url)  # get response
        bgp_updates = None

        if update_response.status_code == 200:
            update_data = update_response.json()
            self.nr_updates = update_data["data"][
                "nr_updates"]  # number of updates
            bgp_updates = update_data["data"]["updates"]
            for update in bgp_updates:  # loop through updates
                type_of_update = update["type"]
                if type_of_update == "A":  # Announcement updates
                    path_length = len(update["attrs"]["path"])  # path length
                    path = update["attrs"]["path"]  # actual AS path
                    source_id = update["attrs"][
                        "source_id"]  # source id that originates the announcement
                    peer_ip = source_id.replace(f"{self.collector}-",
                                                "")
                    community = update["attrs"]["community"]  # bgp community
                    # append to lists to add to models
                    self.raw_path_lengths.append(path_length)
                    self.raw_paths.append(path)
                    self.raw_community.append(community)
                    self.update_peers(peer_ip)

            self.train_models()  # 'train' the models
        else:
            print("error connecting to ripe database")
            sys.exit(1)

        return None

    def train_models(self):
        """
            calls each train sub method
        :return: None
        """
        self.train_path_lengths()
        self.train_paths()
        self.train_community()
        return None

    def train_path_lengths(self):
        """
            'train' path lengths
        :return: None
        """
        self.count_occurrences(self.path_length_model, self.raw_path_lengths)
        return None

    def train_paths(self):
        """
            'train' paths
        :return: None
        """
        self.count_occurrences(self.path_model, self.raw_paths, True)
        return None

    def train_community(self):
        """
            'train' community
        :return: None
        """
        self.count_occurrences(self.community_model, self.raw_community, True)
        return None

    def calculate_ratios(self, path_length, path, community):
        """
            Calculate the frequency a specific announcement's attributes
            have been previously announced.

            :return [path_length ratio, ip ratio, path ratio, community ratio]
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

        return [path_length_trust, path_trust, comm_trust]

    def receive_update(self, start, end):
        """
        An update of bgp Updates to apply our frequency analysis to detect
        potential harmful announcement. Updates 'trust' of a BGP Collector.
        :param start: array of start times
        :param end: array of end times
        :return: None
        """
        for i in range(len(start)):  # loop through starttimes
            start_time = start[i]
            end_time = end[i]
            # url to connect to ripe
            update_url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
                         f"&rrcs={self.collector}&starttime={start_time}&endtime={end_time}"
            update_response = requests.get(update_url)  # ripe data response
            bgp_updates = None
            global leader  # current bgp leader
            if update_response.status_code == 200:
                update_data = update_response.json()  # get data
                self.nr_updates += update_data["data"]["nr_updates"]
                bgp_updates = update_data["data"]["updates"]

                self.raw_path_lengths = []  # data to process
                self.raw_paths = []
                self.raw_community = []
                for update in bgp_updates:
                    type_of_update = update["type"]
                    if type_of_update == "A":
                        path_length = len(
                            update["attrs"]["path"])  # path length
                        path = update["attrs"]["path"]  # AS path
                        source_id = update["attrs"]["source_id"]
                        peer_ip = source_id.replace(f"{self.collector}-",
                                                    "")
                        community = update["attrs"]["community"]

                        # append to lists to process data
                        self.raw_path_lengths.append(path_length)
                        self.raw_paths.append(path)
                        self.raw_community.append(community)

                        # calculate the frequencies
                        with mutex:
                            trust_vals = self.calculate_ratios(path_length,
                                                               path,
                                                               community)
                            self.update_peers(peer_ip, trust_vals)

                with mutex:
                    self.train_models()  # train our local models
                    save_trust_for_graph()  # save trust to print data later
                    if self is not leader:  # send new data to leader
                        # send local model to leader
                        self.send_local_models(self.raw_path_lengths,
                                               self.raw_paths,
                                               self.raw_community)
        return None

    def send_local_models(self, path_length, path, community):
        """
            Send local model to leader
            :return None
        """
        global leader
        if leader is None:
            self.elect_leader()
        if self is not leader:
            leader.update_models(path_length, path, community)
        return None

    def elect_leader(self):
        """
            Elect a new leader to handle coordination and hold central model
        :return:
        """
        global leader
        global collectors
        highest_id = -1
        new_leader = None
        print("hi")

        for collector in collectors:
            if collector.collector > highest_id:
                new_leader = collector
                highest_id = collector.collector

        leader = new_leader
        return None


    def update_models(self, path_length, path_model,
                      community_model):
        """
            Update Models from peer bgp collector
            :return None
        """
        """ Path length """
        for value in path_length:
            if value in self.path_length_model:
                self.path_length_model[value] += 1
            else:
                self.path_length_model[value] = 1

        """Paths """
        for value in path_model:
            value = tuple(value)
            if value in self.path_model:
                self.path_model[value] += 1
            else:
                self.path_model[value] = 1

        """BGP Community"""
        for value in community_model:
            value = tuple(value)
            if value in self.community_model:
                self.community_model[value] += 1
            else:
                self.community_model[value] = 1

        global leader
        global collectors
        # send the central (leaders) model to all the collectors
        if self is leader:
            for collector in collectors:
                if collector is not self:
                    collector.receive_central_model(self.path_length_model,
                                                    self.path_model,
                                                    self.community_model)
        return None

    def receive_central_model(self, path_length_model, path_model,
                              community_model):
        """ Update local model from the central model
            :return None
        """
        self.path_length_model = path_length_model
        self.path_model = path_model
        self.community_model = community_model
        return None


def save_trust_for_graph():
    """
        Save trust values to print graph
        :return None
    """
    global collectors
    global trust_over_time
    global bgp_peers

    for peer in bgp_peers:
        if peer.ip in trust_over_time:
            trust_over_time[peer.ip].append(peer.trust)
        else:
            trust_over_time[peer.ip] = [peer.trust]

    """    for collector in collectors:
        for bgp_peer in collector.bgp_peers:
            if bgp_peer.ip in trust_over_time:
                trust_over_time[bgp_peer.ip].append(bgp_peer.trust)
            else:
                trust_over_time[bgp_peer.ip] = [bgp_peer.trust]"""
    return None


def plot_line_graph(name):
    """
        Plot the trust graph for analysis
        :return: None
    """
    global collectors
    global trust_over_time
    num_updates_for_plotting = 0
    for key, value in trust_over_time.items():
        if len(value) > num_updates_for_plotting:
            num_updates_for_plotting = len(value)

    x_values = [x + 1 for x in
                range(num_updates_for_plotting)]  # number of updates (x-axis)

    for key, value in trust_over_time.items():
        num_updates = len(value)
        if num_updates < 15:
            continue
        if num_updates != num_updates_for_plotting:
            for i in range(num_updates_for_plotting - num_updates):
                value.append(value[-1])
        plt.plot(x_values, value, label=f"BGP Peer: {key}")

    plt.xlabel('Time')
    plt.ylabel('Trust Value')
    plt.title('Trust Value Over Time for Each BGP Peer')
    # plt.legend()
    plt.savefig(f'{name}')
    plt.show()


def plot_bar_graph(name):
    """
        Plot the trust graph for analysis
        :return: None
    """
    global collectors
    global trust_over_time

    for key, value in trust_over_time.items():
        final_trust = value[-1]
        plt.bar(key, final_trust)

    plt.xlabel('BGP Peer')
    plt.ylabel('Trust Value')
    plt.title('\"Final\" Trust Value of BGP Peer')
    plt.xticks([])
    plt.savefig(f'{name}')

    plt.show()


def update(bgp_collector: BGPCollector, start, end):
    """
        Function that threads call to start the updates for the collectos
        :param bgp_collector: collector
        :param start: list of start times
        :param end:   list of end times
        :return: None
    """
    bgp_collector.receive_update(start, end)
    return None


def example_main():
    name = input("Enter name of site you intend to use: ")
    ip = input("Enter the IP of site: ")
    print(
        "running simulation... may take a minute, going through 7 months of BGP data")

    startime = "2023-6-01T17:59:51"
    endtime = "2023-09-01T17:59:51"
    bgp_collector_11 = BGPCollector(ip, "11", startime, endtime)
    bgp_collector_14 = BGPCollector(ip, "14", startime, endtime)
    bgp_collector_16 = BGPCollector(ip, "16", startime, endtime)
    bgp_collector_21 = BGPCollector(ip, "21", startime, endtime)

    start_update_times = ["2023-09-01T17:59:52", "2023-10-01T17:59:52",
                          "2023-11-01T17:59:52", "2023-12-01T17:59:52",
                          "2024-01-01T17:59:52", "2024-02-01T17:59:52",
                          "2024-03-01T17:59:52", "2024-04-01T17:59:52",
                          "2024-05-01T17:59:52"]
    end_update_times = ["2023-10-01T17:59:51", "2023-11-01T17:59:51",
                        "2023-12-01T17:59:51", "2024-01-01T17:59:51",
                        "2024-02-01T17:59:51", "2024-03-01T17:59:51",
                        "2024-04-01T17:59:51", "2024-05-01T17:59:51",
                        "2024-05-19T17:59:51"]

    global collectors
    collectors = [bgp_collector_11, bgp_collector_14, bgp_collector_16,
                  bgp_collector_21]
    collector_threads = []

    global leader
    leader = collectors[0]

    for collector in collectors:
        collector.collect_initial_data()

    for collector in collectors:
        collector.send_local_models(collector.raw_path_lengths,
                                    collector.raw_paths,
                                    collector.raw_community)

    for collector in collectors:
        worker = threading.Thread(target=update, args=(
            collector, start_update_times, end_update_times))
        collector_threads.append(worker)
        worker.start()

    for worker in collector_threads:
        worker.join()

    plot_line_graph(f"{name}-line-graph.png")

    plot_bar_graph(f"{name}-bar-graph.png")

    output_file_path = f'{name}.txt'

    with open(output_file_path, 'w') as file:
        global bgp_peers
        for peer in bgp_peers:
            file.write(
                f"{peer.ip}: has trust {peer.trust}"'\n')

        """        for collector in collectors:
            for item in collector.bgp_peers:
                file.write(
                    f"{item.ip}: has trust {item.trust}"'\n')
                    """

    print("Simulation complete. Files with data saved locally.")


if __name__ == "__main__":
    example_main()
