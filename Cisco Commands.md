# CISCO Commands
## BGP
#### Enable BGP on router
```
R1(config)# router bgp 1
```

#### Configure router id
```
R1(config-router)# bgp router-id 1.1.1.1
```

#### Configure neighbors
Adds the IP address of the neighbor in the specified AS
```
R1(config-router)# neighbor 12.0.0.2 remote-as 2
```

#### Configure networks
Specifies a network as local to this AS
```
R1(config-router)# network 139.100.0.1 mask 255.255.255.252
```
#### Show
```
R1# show ip route
R1# show ip protocols
```
<br />


## IPv6 TUNNEL
```
R1(config)# interface Tunnel23
R1(config-if)# no ip address
R1(config-if)# mtu 1476
R1(config-if)# ipv6 address FC00:1:1:1::2/64
R1(config-if)# tunnel source GigabitEthernet0/0	
R1(config-if)# tunnel destination 139.104.0.2
R1(config-if)# tunnel mode ipv6ip
```
<br />
