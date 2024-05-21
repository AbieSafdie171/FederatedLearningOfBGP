import requests  # to connect to ripe database
import math     # math!
import matplotlib.pyplot as plt     # plotting library
import threading  # to run multiple collectors in parallel

leader = None   # bgp collector who acts as leader
collectors = None   # list of collectors
trust_over_time = []    # trust values for plotting
mutex = threading.Lock()    # lock for mutual exclusion across threads


class BGPCollector:
    """
    BGP Collector Object
    """
    def __init__(self, ip_prefix, collector, starttime, endtime):
        """
        :param ip_prefix: ip that we are collecting updates for
        :param collector: collector number
        :param starttime: initial starttime to collect data to use
        :param endtime: initial endtime to collect data to use
        """
        self.collector = collector
        self.trust = 1000       # start default trust at 1000
        self.ip_prefix = ip_prefix
        self.starttime = starttime
        self.endtime = endtime
        self.nr_updates = None      # number of updates
        self.raw_paths = []         # new update paths get stored here
        self.raw_path_lengths = []  # new path lengths
        self.raw_community = []     # new bgp communities
        self.raw_source_ips = []    # new ips that sent the update
        self.path_length_ratio = None   # frequency of new route to old
        self.ip_ratio = None            # frequency of new route to old
        self.path_ratio = None          # frequency of new route to old
        self.comm_ratio = None          # frequency of new route to old
        self.path_length_model = {}     # dict containing path length mapped to how many times it occured
        self.ip_model = {}              # dict containing ips mapped to how many times it occured
        self.path_model = {}            # dict containing paths mapped to how many times it occured
        self.community_model = {}       # dict containing bgp communities mapped to how many times it occured
        self.withdrawal_ip_model = {}

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
                dictionary[value] += 1      # increment occurrence
            else:
                dictionary[value] = 1       # set key-value pair
        return None

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
            self.nr_updates = update_data["data"]["nr_updates"] # number of updates
            bgp_updates = update_data["data"]["updates"]
            for update in bgp_updates:      # loop through updates
                type_of_update = update["type"]
                if type_of_update == "A":      # Announcement updates
                    path_length = len(update["attrs"]["path"])  # path length
                    path = update["attrs"]["path"]  # actual AS path
                    source_id = update["attrs"]["source_id"]    # source id that originates the announcement
                    source_id = source_id.replace(f"{self.collector}-",
                                                  "")
                    source_id = ip_to_integer(source_id)
                    community = update["attrs"]["community"]    # bgp community

                    # append to lists to add to models
                    self.raw_path_lengths.append(path_length)
                    self.raw_paths.append(path)
                    self.raw_community.append(community)
                    self.raw_source_ips.append(source_id)

            self.train_models()     # 'train' the models
        else:
            print("error connecting to ripe database")

        return None

    def train_models(self):
        """
            calls each train sub method
        :return: None
        """
        self.train_path_lengths()
        self.train_ip()
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

    def train_ip(self):
        """
            'train' ip origin
        :return: None
        """
        self.count_occurrences(self.ip_model, self.raw_source_ips)
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

    def calculate_ratios(self, path_length, ip, path, community):
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
        """
        An update of bgp Updates to apply our frequency analysis to detect
        potential harmful announcement. Updates 'trust' of a BGP Collector.
        :param start: array of start times
        :param end: array of end times
        :return: None
        """
        for i in range(len(start)):     # loop through starttimes
            start_time = start[i]
            end_time = end[i]
            # url to connect to ripe
            update_url = f"https://stat.ripe.net/data/bgp-updates/data.json?resource={self.ip_prefix}" \
                         f"&rrcs={self.collector}&starttime={start_time}&endtime={end_time}"
            update_response = requests.get(update_url)  # ripe data response
            bgp_updates = None
            global leader   # current bgp leader
            if update_response.status_code == 200:
                update_data = update_response.json()    # get data
                self.nr_updates += update_data["data"]["nr_updates"]
                bgp_updates = update_data["data"]["updates"]

                self.raw_path_lengths = []  # data to process
                self.raw_source_ips = []
                self.raw_paths = []
                self.raw_community = []
                for update in bgp_updates:
                    type_of_update = update["type"]
                    if type_of_update == "A":
                        path_length = len(update["attrs"]["path"]) # path length
                        path = update["attrs"]["path"]              # AS path
                        source_id = update["attrs"]["source_id"]
                        source_id = source_id.replace(f"{self.collector}-",
                                                      "")
                        source_id = ip_to_integer(source_id)  # source id that originates the announcement
                        community = update["attrs"]["community"]

                        # append to lists to process data
                        self.raw_path_lengths.append(path_length)
                        self.raw_paths.append(path)
                        self.raw_source_ips.append(source_id)
                        self.raw_community.append(community)

                        # calculate the frequencies
                        trust_vals = self.calculate_ratios(path_length,
                                                           source_id, path,
                                                           community)
                        self.update_trust(trust_vals)   # update local collectors trust

                with mutex:
                    self.train_models()     # train our local models
                    save_trust_for_graph()  # save trust to print data later
                    if self is not leader:  # send new data to leader
                        # send local model to leader
                        self.send_local_models(self.raw_path_lengths,
                                               self.raw_source_ips,
                                               self.raw_paths,
                                               self.raw_community)
                    # call for election for new leader
                    if self.check_for_election():
                        self.call_election()    # call election
        return None

    def update_trust(self, trust_vals):
        """
        Apply trust algorithm to update trust based on data
        :param trust_vals: frequencies of given data
        :return: None
        """
        val = 0     # value to add to trust
        k = 0.1     # todo
        for i in range(len(trust_vals)):
            d = 0.1  # todo
            # if path attribute and if new announcement (<0.01) apply greater weight
            if trust_vals[i] <= 0.01 and i == 2:
                d = 10

            tmp = (1 - math.exp(-k * abs(10 * trust_vals[i] - 1))) * math.copysign(1, 10 * trust_vals[i] - 1) * d

            val += tmp

        self.trust += val   # update trust
        return None

    def send_local_models(self, path_length, source_id, path, community):
        """
            Send local model to leader
            :return None
        """
        global leader
        if self is not leader:
            leader.update_models(path_length, source_id,
                                 path, community)
        return None

    def update_models(self, path_length, ip_model, path_model,
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

        """ IP """
        for value in ip_model:
            if value in self.ip_model:
                self.ip_model[value] += 1
            else:
                self.ip_model[value] = 1

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
                                                    self.ip_model,
                                                    self.path_model,
                                                    self.community_model)
        return None

    def receive_central_model(self, path_length_model, ip_model, path_model,
                              community_model):
        """ Update local model from the central model
            :return None
        """
        self.path_length_model = path_length_model
        self.ip_model = ip_model
        self.path_model = path_model
        self.community_model = community_model
        return None

    def check_for_election(self):
        """
            Check to see if an election needs to be called
        :return: bool
        """
        global leader
        if self.trust > leader.trust:
            return True
        return False

    def call_election(self):
        """
            Election by bullying. Collector with the highest trust
            becomes the leader
        :return: None
        """
        global collectors
        global leader
        for collector in collectors:
            if collector.trust > leader.trust:
                leader = collector
        return None


def save_trust_for_graph():
    """
        Save trust values to print graph
        :return None
    """
    global collectors
    global trust_over_time
    collector_names = [collector.collector for collector in collectors]
    trust_values = [collector.trust for collector in collectors]
    trust_over_time.append(trust_values)
    return None


def plot_graph(name):
    """
        Plot the trust graph for analysis
        :return: None
    """
    global collectors
    global trust_over_time
    x_values = [x + 1 for x in range(len(trust_over_time))]  # number of updates (x-axis)

    for i in range(len(collectors)):
        collector_trust = [trust[i] for trust in trust_over_time]   # trust (y-axis)
        plt.plot(x_values, collector_trust,
                 label=f"Collector {collectors[i].collector}")

    plt.xlabel('Update')
    plt.ylabel('Trust Value')
    plt.title('Trust Value Over Time for Each Collector')
    plt.legend()
    plt.tight_layout()
    plt.savefig(f'{name}')
    plt.show()




def ip_to_integer(ip_address):
    """
        Converts from 255.255.255.255 format to integer for ease of comparison
        :param ip_address: ip in 255.255.255.255 format
        :return: ip as integer representation
    """
    octets = ip_address.split('.')  # split into octets

    binary_ip = ''
    for octet in octets:    # convert to binary
        binary_octet = bin(int(octet))[2:].zfill(8)
        binary_ip += binary_octet

    return int(binary_ip, 2)    # convert to int


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

if __name__ == "__main__":

    # 208.65.153.238 = youtube
    # 140.211.0.0/16 = uoregon

    startime = "2023-6-01T17:59:51"
    endtime = "2023-09-01T17:59:51"
    bgp_collector_11 = BGPCollector("208.65.153.238", "11", startime, endtime)
    bgp_collector_14 = BGPCollector("208.65.153.238", "14", startime, endtime)
    bgp_collector_16 = BGPCollector("208.65.153.238", "16", startime, endtime)
    bgp_collector_21 = BGPCollector("208.65.153.238", "21", startime, endtime)

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

    collectors = [bgp_collector_11, bgp_collector_14, bgp_collector_16,
                  bgp_collector_21]
    collector_threads = []

    leader = collectors[0]

    for collector in collectors:
        collector.collect_initial_data()

    for collector in collectors:
        collector.send_local_models(collector.raw_path_lengths,
                                    collector.raw_source_ips,
                                    collector.raw_paths,
                                    collector.raw_community)

    for collector in collectors:
        worker = threading.Thread(target=update, args=(
            collector, start_update_times, end_update_times))
        collector_threads.append(worker)
        worker.start()

    for worker in collector_threads:
        worker.join()

    for collector in collectors:
        print(f"Collector {collector.collector} has trust {collector.trust}")

    plot_graph("youtube.png")

