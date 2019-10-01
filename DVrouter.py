####################################################
# DVrouter.py
# Names: Jiachen Wang
# Names: Chang Lee
# Penn IDs: 49678282
# Penn IDs: 23888214
#####################################################

import sys
from collections import defaultdict
from router import Router
from packet import Packet
from json import dumps, loads




class DVrouter(Router):
    """Distance vector routing protocol implementation."""

    def __init__(self, addr, heartbeatTime):
        """TODO: add your own class fields and initialization code here"""
        Router.__init__(self, addr)  # initialize superclass - don't remove
        # so it has a destination address, a nextHop, a cost
        # use dictionary,router has a table
       
        self.routing_table = {}
        self.hearbeatTime = heartbeatTime
        self.lastTime = 0
        self.infinity = 16
        self.neighboursPort = {}
        self.neighboursAddr = {}
       
        

    def handlePacket(self, port, packet):
        """TODO: process incoming packet"""
        # We should use that port to find who send us the packet!!!
        # Port is where the packet arrives
        
        if packet.kind == Packet.ROUTING:
            content = packet.getContent()
            new_table = loads(content)
            neighbor_addr = packet.srcAddr
            
            if self.updateTable(neighbor_addr, new_table):
                # Table has been updated
                # broadcasting the packet
                self.broadcast()
                                                      
                 
        elif packet.kind == Packet.TRACEROUTE:
            # if it is traceroute, we just forward it
            correct_port = None
  
            for key in self.routing_table:
                if (key == packet.dstAddr):
                    correct_port = self.routing_table[key]['egress']
                    break

            if (correct_port != None):
                self.send(correct_port, packet)
                 
    def handleNewLink(self, port, endpoint, cost):
        """TODO: handle new link"""

        self.neighboursPort[port] = endpoint
        self.neighboursAddr[endpoint] = {'port': port, 'cost': cost }

        if endpoint not in self.routing_table :       
            self.routing_table[endpoint] = {'cost': cost, 'nextHop': endpoint, 'egress': port}
            
            self.broadcast()

        else:
          
            if cost < self.routing_table[endpoint]['cost']:
                # we have a better route    
                self.routing_table[endpoint] = {'cost': cost, 'nextHop': endpoint, 'egress': port}
              
                self.broadcast()
            

      
                
                        
    def handleRemoveLink(self, port):
        """TODO: handle removed link"""
              
        neighbor_addr = self.neighboursPort[port]
        del self.neighboursPort[port]
        del self.neighboursAddr[neighbor_addr]   

        for key in self.routing_table:
            
            if (self.routing_table[key]['egress']== port):   
                
                self.routing_table[key]['cost'] = self.infinity
                self.routing_table[key]['nextHop'] = ''
                self.routing_table[key]['egress']== -1
               
        self.broadcast()        

        
        

    def handleTime(self, timeMillisecs):
        """TODO: handle current time"""
        if (timeMillisecs - self.lastTime) >= self.hearbeatTime:
            self.broadcast()

        self.lastTime = timeMillisecs
            

    def debugString(self):
        """TODO: generate a string for debugging in network visualizer"""
        #print ("not good")
        return ""


    def broadcast(self):
        
        new_content = dumps(self.routing_table)
        for port in self.neighboursPort:   
            packet = Packet(Packet.ROUTING, self.addr, self.neighboursPort[port], new_content)
            self.send(port, packet)
    
     
    # design a updateTable function, return true if we need to update the table, false otherwise
    # the arguments are neighbor_addr and the new_table. neighbor_addr is the neighbor who send us the packet
    # new_table is the content of its packet.   
    def updateTable(self, neighbor_addr, new_table):
        
        # use this function to check if you need to update the Table or not
        # if return false, it means that there is no update, we just don't need to send
        # if return true, it means that the data has been updated, so we need to send packets
        # we need to have a flag to check if we need to update our table.
        flag= False

        cost_to_neighbor = self.routing_table[neighbor_addr]['cost']
        
        for destAddr in new_table:
            if destAddr not in self.routing_table:
                if(destAddr == self.addr):
                        
                    if(new_table[destAddr]['cost']< self.routing_table[neighbor_addr]['cost']):
                        self.routing_table[neighbor_addr]['cost'] = new_table[destAddr]['cost']
                        flag = True

                elif((new_table[destAddr]['cost']+ cost_to_neighbor) < self.infinity):
                    flag = True
                        # means we don't have this table entry in our table
                    self.routing_table[destAddr] = {'cost': (cost_to_neighbor + new_table[destAddr]['cost']), 'nextHop': self.routing_table[neighbor_addr]['nextHop'], 'egress': self.routing_table[neighbor_addr]['egress']}

                elif((new_table[destAddr]['cost']+ cost_to_neighbor) >= self.infinity):
                        
                    # means we don't have this table entry in our table, but it is infinity
                    # so we set it as infinity
                    flag = True
                    self.routing_table[destAddr] = {'cost': self.infinity, 'nextHop': '', 'egress': -1}


            else:       
                cost_now = self.routing_table[destAddr]['cost']
                cost_through = cost_to_neighbor + new_table[destAddr]['cost']    
               
                if cost_through > self.infinity:
                    cost_through = self.infinity


                if cost_through < cost_now:
                # we found a better route   
                    self.routing_table[destAddr]['cost'] = cost_through
                    self.routing_table[destAddr]['nextHop'] = neighbor_addr
                    self.routing_table[destAddr]['egress'] = self.routing_table[neighbor_addr]['egress']

                    flag = True

               
                elif neighbor_addr == self.routing_table[destAddr]['nextHop']:
                        # we need to go through this neighbour to get to the destination
                    if cost_through != cost_now:

                        if cost_through == self.infinity:
                        
                            if destAddr in self.neighboursAddr: 
                            # This means that the destination is our neighbour, so we go there directly
                                self.routing_table[destAddr]['cost'] = self.neighboursAddr[destAddr]['cost']         
                                self.routing_table[destAddr]['nextHop'] = destAddr
                                self.routing_table[destAddr]['egress'] = self.neighboursAddr[destAddr]['port']
                                    
                            else:
                                    # It is not our neighbour, we sould set that destination unreachable
                                self.routing_table[destAddr]['cost'] = self.infinity
                                self.routing_table[destAddr]['nextHop']= ''
                                self.routing_table[destAddr]['egress'] = -1
            

                        else:
                                # cost_through is not infinity, we should update
                            self.routing_table[destAddr]['cost'] = cost_through
                            
                            
                        flag = True

        
        return flag                
                        
                
        
     
