# Intradomain-Routing-Algorithms


The Internet is composed of many independent networks (called autonomous systems) that must cooperate in order for packets to reach their destinations. This necessitates different protocols and algorithms for routing packet within autonomous systems, where all routers are operated by the same entity, and between autonomous systems, where business agreements and other policy considerations affect routing decisions.

This project focuses on intradomain routing algorithms used by routers within a single autonomous system (AS). The goal of intradomain routing is typically to forward packets along the shortest or lowest cost path through the network.

The need to rapidly handle unexpected router or link failures, changing link costs (usually depending on traffic volume), and connections from new routers and clients, motivates the use of distributed algorithms for intradomain routing. In these distributed algorithms, routers start with only their local state and must communicate with each other to learn lowest cost paths.

Nearly all intradomain routing algorithms used in real-world networks fall into one of two categories, distance-vector or link-state. In this project, we implemented distributed distance-vector and link-state routing algorithms in Python and test them with a provided network simulator.

