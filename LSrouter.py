####################################################
# LSrouter.py
# Names: Chang Hyun Lee, Jiachen Wang
# Penn IDs: 23888214, 49678282
#####################################################

import sys
from collections import defaultdict
from router import Router
from packet import Packet
from json import dumps, loads
import math



class LSrouter(Router):
    """Link state routing protocol implementation."""

    """
        initialize LSrouter with the following data members
        - neighbours             a map-based data structure which has the addresses of neighbours as keys and 
                                {
                                    'cost'          :       "cost to reach that neighbor", 
                                    'port'          :       "the port number ro reach that the neighbor",
                                }
                                as values

        - tentative             a map-based data structure whose key is endpoint and whose value is the following format
                                {
                                    'cost'         :       "cost to reach that endpoint", 
                                    'nextHop'      :       "the address of the neighbor to reach that endpoint",
                                }

        - confirmed             a map-based data structure which has the same data structure as tentative
                                this data structure only accepts the entry whose cost to reach that endpoint is minimum among all
                                and this data structure is processed in handlePacket
                                {
                                    'cost'         :       "minimum cost to reach that endpoint", 
                                    'nextHop'      :       "the address of the neighbor to reach that endpoint",
                                    'justAdded'    :       "a boolean variable indicating whether the entry was added now"
                                }

        - router_packets        a map-based data structure whose key is the address of router
                                and a value is the content in json received from the packet

        - seqNum                a sequence number for link state packet (LSP) to send. This value gets incremented every time
                                a new LSP is generated. 

        - lastTime              the most recent time LSP was sent from this router

        - ttl                   a time to live for the LSP of the router; it will be heartbeat

    """
    def __init__(self, addr, heartbeatTime):
        """TODO: add your own class fields and initialization code here"""
        Router.__init__(self, addr)  # initialize superclass - don't remove
        self.neighbours = {}
        self.tentative = {} 
        self.confirmed = {} # this is equivalent to routing_table in DV
        self.confirmed[addr] = {'cost' : 0, 'nextHop' : "", 'justAdded' : True} # QUESTION1
        self.seqNum = 1
        self.lastTime = 0 # the last time LSP was sent
        self.ttl = heartbeatTime # QUESTION2
        self.router_packets = {}

        self.router_packets[addr] = {
            #'nodeID' : self.addr,
            'neighbours' : self.neighbours,
            'seqNum' : self.seqNum,
            #'ttl' : self.ttl
        } 

    """
        a function that checks 
            1. whether a received packet is from the address not included in router_packets or
            2. whether a received packet has more recent sequence number than the packet 
                associated with the same source address as packet

        - packet_address_param          the source address of the packet
        - new_sequence_num_param        the sequence number of the packet
    """
    def isNewPacket(self, packet_address_param, new_sequence_num_param):

        if packet_address_param not in self.router_packets.keys():
             # if the router (packet.srcAddr) is not in the packets data structure, add it
            return True
        else:
            # if the source address is present in router_packet, 
            # check the sequence number of the packet associated with that address
            if (new_sequence_num_param > self.router_packets[packet_address_param]['seqNum']):
                # if the sequence number from the recent packet is greater than the packet stored in
                # router_packet, update it
                return True
            else:
                return False

        return False

    """
        a function that process neighbours of Next
    """
    def processNeighborOfNext(self, next_addr, neighbours_of_next):
        for neighbor_addr in neighbours_of_next.keys(): # for each neighbor of next
            # calculate the cost to reach the neighbor of next
            # it is the sum of 
            #   1. the cost to reach from the router itself to next and 
            #   2. the cost to reach from next to the neightbor
            cost_to_reach_neighbor = self.confirmed[next_addr]['cost'] + neighbours_of_next[neighbor_addr]['cost']

            # check some conditions
            if (neighbor_addr not in self.confirmed.keys()) and (neighbor_addr not in self.tentative.keys()):
                # if neigbhbor of next is neither in confirmed nor tentative, place it in tentative
                if (next_addr == self.addr): # not necessary though
                    self.tentative[neighbor_addr] = {'cost': cost_to_reach_neighbor, 'nextHop': neighbor_addr}
                else:
                    next_hop_to_reach_next = self.confirmed[next_addr]['nextHop'] 
                    self.tentative[neighbor_addr] = {'cost' : cost_to_reach_neighbor, 'nextHop': next_hop_to_reach_next}

            elif (neighbor_addr in self.tentative.keys() and cost_to_reach_neighbor < self.tentative[neighbor_addr]['cost']):
                next_hop_to_reach_next = self.confirmed[next_addr]['nextHop']
                self.tentative[neighbor_addr] = {'cost' : cost_to_reach_neighbor, 'nextHop': next_hop_to_reach_next}        
 
    """
        a function that picks an entry from tentative list with minimum cost and moves it to confirmed
    """
    def processEntryWithMinCost(self):
        minCost = float("inf") # QUESTION3
        addr_min_cost = ''
        # find the entry with min cost 
        for addr_tentative in self.tentative.keys():
            if self.tentative[addr_tentative]['cost'] < minCost:
                minCost = self.tentative[addr_tentative]['cost']
                addr_min_cost = addr_tentative

        self.confirmed[addr_min_cost] = {
            'cost' : self.tentative[addr_min_cost]['cost']
            , 'nextHop' : self.tentative[addr_min_cost]['nextHop']
            , 'justAdded' : True
        } # move the entry to confirmed

        # delete tentative list
        del self.tentative[addr_min_cost]


    def reinitializeList(self):
        self.tentative = {} 
        self.confirmed = {} # this is equivalent to routing_table in DV
        self.confirmed[self.addr] = {'cost' : 0, 'nextHop' : "", 'justAdded' : True} # QUESTION1



    def updateLSP(self):
        for next_addr in self.confirmed.keys():
            if (self.confirmed[next_addr]['justAdded']):
                #print next_addr + " was just added "
                #if (next_addr.isupper()):
                #print "next_addr " + next_addr + " is a router!"
                if (next_addr in self.router_packets):
                    #print "next_addr " + next_addr + " is in self.router_packets"
                    content_in_json_next_addr = self.router_packets[next_addr] # call the LSP associated with next's key
                    neighbours_of_next = content_in_json_next_addr['neighbours'] # call the neighbours of next

                    self.processNeighborOfNext(next_addr, neighbours_of_next) 
                    # calculate the cost to cost_to_reach_neighbor and add newly made entries to tentative
                   
                    """
                    if (any(self.tentative)): 
                        # if there is any element in the dictionary
                        print "tentative is not empty, so call processEntryWithMinCost"
                        self.processEntryWithMinCost()
                    else:
                        # if tentative has no element
                        print "tentative is empty"
                        #break # 
                        # pick the lowest cost from tentative list and break it out
                    """

                    self.confirmed[next_addr]['justAdded'] = False  
                    # QUESTION1
                    # what if there is an updated packet from that next_addr??
                    # mark the flag variable False so that it won't be looked up again
                #else:
                    #print "next_addr " + next_addr + " is NOT in self.router_packets"
                #else:
                    #print "next_addr " + next_addr + " is a client!"

            #else:
                #print "from " + self.addr + ": " + next_addr + " has already been looked up"

    """
        a function that handles packet 
    """
    def handlePacket(self, port, packet):
        """TODO: process incoming packet"""
        if packet.kind == Packet.ROUTING:

            # first, inspect the member variable, 'packets'
            # filter out clients and accept routers only
            content_in_json = loads(packet.getContent()) 

            if self.isNewPacket(packet.srcAddr, content_in_json['seqNum']):
                #print "new packet! "
                # if the packet is from the hop that is not in the list of router_packets or
                # if the packet has more up-to-date sequence number, update it
                self.router_packets[packet.srcAddr] = content_in_json

                # reinitialize Confirmed and Tentative
                self.reinitializeList()
                
                # route calculation
                # iterate over the entries in confirmed
                while True:
                    self.updateLSP()
                    if len(self.tentative) == 0:
                        break
                    else:
                        self.processEntryWithMinCost()

                # broadcast the packets to other neighbors except the one the packet is sent from
                self.broadcastLSP(port, packet)
            #else:
                #print "no new packet!"
        
        elif packet.kind == Packet.TRACEROUTE:
            # if it is traceroute, we just forward it
            correct_port = None
  
            for endpoint in self.confirmed:
                if (endpoint == packet.dstAddr):
                    #print "going from " + packet.srcAddr + " to " + packet.dstAddr
                    #print "reach from " + packet.srcAddr + " to " + packet.dstAddr
                    next_hop = self.confirmed[endpoint]['nextHop']
                    if (next_hop == ''):
                        correct_port = -1
                    else:
                        #print "next_hop is" + next_hop # QUESTION4
                        #correct_port = self.neighbours[next_hop]['port']
                        # QUESTION5
                        # if I used the if statements above, it works well for small_net_events
                        # but it doesn't work for pg244
                        if (next_hop in self.neighbours):
                            correct_port = self.neighbours[next_hop]['port']
                        else:
                            correct_port = -1
                    break

            if (correct_port != None):
                self.send(correct_port, packet)


    def handleNewLink(self, port, endpoint, cost):
        """
            To-do
            
            - generate a new LSP (call sendLSPPacket) in every if statement
        """
        self.neighbours[endpoint] = {'cost' : cost, 'port' : port}
        self.router_packets[self.addr]['neighbours'] = self.neighbours
        self.generateLSP() # because new link has been added, generate a new LSP 


    def handleRemoveLink(self, port):
        """
            To-do
            - if a link is removed, generate a new LSP (call sendLSPPacket)
        """
        for endpoint in self.neighbours.keys():
            if (self.neighbours[endpoint]['port'] == port):

                del self.neighbours[endpoint] #= {'cost' : cost, 'port' : port}
                del self.router_packets[endpoint]
                if (self.addr in self.router_packets
                    and self.router_packets[self.addr]['neighbours'] != None 
                    and endpoint in self.router_packets[self.addr]['neighbours']
                    ):
                    #print self.router_packets[self.addr]['neighbours']
                    del self.router_packets[self.addr]['neighbours'][endpoint]

                self.generateLSP() # because a link has been deleted, generate a new LSP 
        #pass


    def handleTime(self, timeMillisecs):
        """
            compare the current time and and last time LSP was sent from this router, and if the 
            difference is greater than the time-to-live (TTL) of this router, then generate anther 
            new LSP.
        """
        if (timeMillisecs - self.lastTime)>= self.ttl:
            self.generateLSP()
            self.lastTime = timeMillisecs



    def debugString(self):
        """TODO: generate a string for debugging in network visualizer"""

        debugStr = "\n"
        debugStr = debugStr + "============router " + self.addr + "============\n"
        # router_packets (LSP)
        debugStr = debugStr + "1. router_packets\n"
        for addr in self.router_packets:
            entry = addr + "--->" + str(self.router_packets[addr])
            debugStr = debugStr + entry + "\n"

        # tentative
        debugStr = debugStr + "2. tentative\n"
        for addr in self.tentative:
            entry = addr + "--->" + str(self.tentative[addr])
            debugStr = debugStr + entry + "\n"


        # confirmed
        debugStr = debugStr + "3. confirmed\n"
        for addr in self.confirmed:
            entry = addr + "--->" + str(self.confirmed[addr])
            debugStr = debugStr + entry + "\n"
        

        debugStr = debugStr + "============router " + self.addr + "============\n"
        return debugStr 

    """
        a method to generate a new LSP packet and broadcasts to neighbors. 
        This must be called under two conditions/
        1. the packet sent before has already expired (compare TTL)
        2. there is a change in the structure of the network (adding/removing link) 
        --> will cause update in sequence number
    """
    def generateLSP(self):
        # formulate content for LSP as specified by textbook (LSP)
        content_in_json = {
            'nodeID' : self.addr,
            'neighbours' : self.neighbours,
            'seqNum' : self.seqNum
            #'ttl' : self.ttl # this may not be necessary
        } 
        new_content = dumps(content_in_json)

        # send packet to neighbours
        for neighborAddr in self.neighbours.keys():   
            packet = Packet(Packet.ROUTING, self.addr, neighborAddr, new_content)
            self.send(self.neighbours[neighborAddr]['port'], packet)

        # increment the sequence number by 1
        self.seqNum = self.seqNum + 1



    """
        a function that broadcasts the RECEIVED packet to all neighbors except the port that the 
        packet is sent from.

        - port              the port the packet is received from
        - packet            the packet instance
    """
    def broadcastLSP(self, port, packet):

        for neighborAddr in self.neighbours.keys():
            if (port != self.neighbours[neighborAddr]['port'] and packet.srcAddr != neighborAddr):
                self.send(self.neighbours[neighborAddr]['port'], packet)
        
        # content_in_json = {
        #      #'nodeID' : self.addr,
        #      'neighbours' : self.neighbours,
        #      'seqNum' : self.seqNum,
        #      'ttl' : self.ttl # this may not be necessary
        #  } 
        # new_content = dumps(content_in_json) 
        
        # for neighborAddr in self.neighbours.keys():
        #     if (port != self.neighbours[neighborAddr]['port']):
        #         packet = Packet(Packet.ROUTING, self.addr, neighborAddr, new_content)
        #         self.send(self.neighbours[neighborAddr]['port'], packet)

        # # increment the sequence number by 1
        
        # self.seqNum = self.seqNum + 1
        
        




