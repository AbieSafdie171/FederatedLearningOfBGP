import random
import time


class Node:
    def __init__(self, ip, autonomous_system, router):
        self.ip = ip
        self.autonomous_system = autonomous_system
        self.router = router
        self.messages = []
        if self.ip not in self.router.nodes:
            self.router.nodes.append(self)

    def send_message(self, dest_ip, msg):
        self.router.forward_message(dest_ip, msg)

    def receive_message(self, msg):
        self.messages.append(msg)


class Router:
    def __init__(self, router_id):
        self.router_id = router_id
        self.neighboring_routers = {}
        self.nodes = []

    def update_neighbor(self, neighbor, cost):
        self.neighboring_routers[neighbor] = cost
        neighbor.neighboring_routers[self] = cost





class InternalRouter(Router):
    def __init__(self, router_id):
        super().__init__(router_id)
        self.routing_table = {}
        self.distance_vector = {}  # Distance vector to store distances to other routers

    def forward_message(self, dest_ip, msg):
        for node in self.nodes:
            if dest_ip == node.ip:
                node.receive_message(msg)
                return
        # else forward to next router

    def bgp_announcement(self, dest_ip_range, next_hop_router, cost):
        for router in self.neighboring_routers:
            router.update_table(dest_ip_range, next_hop_router, cost)

    def update_table(self, dest_ip_range, next_hop_router, path):
        if dest_ip_range not in self.routing_table:
            self.routing_table[dest_ip_range] = next_hop_router, path

        # Update distance vector based on the received routing information
        # self.distance_vector[next_hop_router] = self.neighboring_routers[next_hop_router]

        # print(self.neighboring_routers.keys())

        # bellman ford
        for dest_ip_range, (router, path) in self.routing_table.items():
            pass


class ExternalRouter(Router):
    def __init__(self, router_id):
        super().__init__(router_id)
        self.internal_routing_table = {}
        self.external_routing_table = {}
        self.internal_routers = []
        self.external_routers = []

    def forward_message(self, dest_ip):
        pass


class AutonomousSystem:
    def __init__(self, as_id):
        self.as_id = as_id
        self.internal_routers = []
        self.external_routers = []


# Example usage:

# Create routers
router1 = InternalRouter("Router1")
router2 = InternalRouter("Router2")

router1.update_neighbor(router2, 5)

# Add routers to the autonomous system
autonomous_system = AutonomousSystem("AS1")
autonomous_system.internal_routers.append(router1)
autonomous_system.internal_routers.append(router2)

# destination, next-hop, path
router1.bgp_announcement("10.0.0.0/24", router1, ["Router1"])

# print("Router 2 routing table: ", router2.routing_table)
# print("Router 2 distance vector: ", router2.distance_vector)
