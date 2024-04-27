# CCNA2
## VLANs
#### Create and name VLAN
```
S1(config)# vlan <10>
S1(config-if)# name Office
```

#### Assigning ports to vlan
```
S1(config)# interface <f0/5>
S1(config-if)# switchport mode access
S1(config-if)# switchport access vlan <10>
```

#### Show
```
S1# show vlan brief
```
Don't forget to assign IP addresses to the VLANs.
<br />


## TRUNK
#### Setup trunk
Set on the output interface of the switch. You only need to set it on one switch because the DTV is in dynamic auto mode. It is better to set the trunk on both of them statically.
```
S1(config)# interface <f0/1>
S1(config-if)# switchport mode dynamic desirable
```
OR
```
S1(config-if)# switchport mode trunk
```

#### Turn off DTP
```
S1#switchport nonegotiate
```

#### Setup native VLAN and allowed vlan
```
S1(config-if)# switchport trunk native vlan <99>
S1(config-if)# switchport trunk allowed vlan <10,20,99,...>
```

#### Show and Helper
```
S1# show interfaces trunk
S1# show flash
S1(config-if)#switchport trunk encapsulation dot1q
```
LAB: If I have three switches, I set the mode dynamic desirable on the middle one. On the other ones trunk mode.
<br />


## Inter-VLAN Routing on the Router
#### Configure sub-interfaces for each VLAN as specified in the IP address.
For VLAN 3.
```
R1(config)# int <g0/0/1.3>
R1(config-subif)# encapsulation dot1Q 3
R1(config-subif)# ip address <192.168.3.1> <255.255.255.0>
R1(config-subif)# description "xx"
```
I have to set this up on the switch:
```
S1(config)# ip routing
```
<br />


## Layer 3 Switch (Inter-VLAN Routing)
On the output interface of the switch I set this: (LAB: interface: which connects the router).
```
S1(config)# interface <g0/2>
S1(config-if)# no switchport
S1(config-if)# ip address <209.165.200.225> <255.255.255.252>
```
<br />


## EtherChannel
#### Set up a trunk on the connected ports viz. TRUNK.
```
S1# show interfaces trunk
```

#### Secondly, it is necessary to create an EtherChannel.
```
S1(config)# interface range <f0/21 – 22>
S1(config-if-range)# shutdown
S1(config-if-range)# channel-group <1> mode desirable
S1(config-if-range)# no shutdown
```

#### Finally, it is necessary to create a trunk.
```
S1(config)# interface port-channel <1>
S1(config-if)# switchport mode trunk
```
All these settings must be done on all switches.
<br />

##### For PAgP
```
S1(config-if-range)# channel-group <1> mode desirable
```

##### For LACP
```
S1(config-if-range)# channel-group <1> mode active
```

##### For Redundant EtherChannel Link
```
S1(config-if-range)# channel-group <1> mode passive
```
<br />

Port Channel &lt;1&gt; might be is not operative because Spanning Tree Protocol placed some ports into blocking mode. The port channel x port is not functional because the Spanning Tree Protocol has put some ports into blocking mode. You must use the following to unblock it.
```
S1(config)# spanning-tree vlan <1> root primary
```
OR
```
S1(config)# spanning-tree vlan <1> priority 24576
```
<br />

#### Show
```
S1# show interfaces | include Ethernet
S1# show interface status
S1# show interfaces trunk
```
```
S1# show spanning-tree active
S1#show etherchannel summary
```
<br />


## DHCPv4
#### Exclude address
Addresses that have been statically assigned, to devices in the networks, that will use DHCP, must be excluded from the DHCP pools.
```
R2(config)# ip dhcp excluded-address <192.168.10.1> <192.168.10.10>
```

#### Create a DHCP pool.
Network address is the network address that will be assigned by the DHCP server. Default-router is the IP address of the router connected to the DHCP server (I'm setting up a dhcp relay agent here). if there is no other router I set it on the interface of the router towards the devices. DHCP server is the IP address of the DHCP server (entered or selected by me).
```
R2(config)# ip dhcp pool <Name>
R2(dhcp-config)# network <Network address: 192.168.10.0> <subnet: 255.255.255.0>
R2(dhcp-config)# default-router <IP address: 192.168.10.1>
R2(dhcp-config)# dns-server <IP address: 192.1668.20.254>
R2(dhcp-config)# domain-name <ccna-lab.com>
R2(dhcp-config)# lease <days> <hours> <minutes>
```

#### DHCP relay agent.
If there is a router, between the DHCP server and the device (PC, switch...), I set it on that router. Interface towards the device. IP address of the DHCP server interface connected to our router.
```
R1(config)# interface <Example: g0/0>
R1(config-if)# ip helper-address <IP address: 10.1.1.2>
```

#### Get IP address from DHCP server.
```
R1(config)# interface <interface>
R1(config-if)# ip address dhcp
R1(config-if)# no shutdown
```

#### Show
```
R1# show ip dhcp binding
R1# show ip dhcp pool
```


## DHCPv6
#### Stateless
Interface towards the device.
(LAB: there is a switch not a router in the configuration).
```
R1(config)# ipv6 dhcp pool <R1-STATELESS>
R1(config-dhcp)# dns-server <2001:db8:acad::254>
R1(config-dhcp)# domain-name <STATELESS.com>

R1(config)# interface <g0/0/1>
R1(config-if)# ipv6 nd other-config-flag
R1(config-if)# ipv6 dhcp server <R1-STATELESS>
```

#### Stateful
(LAB: there is a router, switch and device, in the configuration).
```
R1(config)# ipv6 dhcp pool <R2-STATEFUL>
R1(config-dhcp)# address prefix <2001:db8:acad:3:aaa::/80>
R1(config-dhcp)# dns-server <2001:db8:acad::254>
R1(config-dhcp)# domain-name <STATEFUL.com>

R1(config)# interface <g0/0/0>
R1(config-if)# ipv6 dhcp server <R2-STATEFUL>
```

#### Relay agent.
Setup on the next router. Interface towards the device.
```
R2(config)# interface <g0/0/1>
R2(config-if)# ipv6 nd managed-config-flag
R2(config-if)# ipv6 dhcp relay destination <2001:db8:acad:2::1> <g0/0/0>
```
<br />


## Dynamic routing (RIP)
#### Enable RIP
```
R1(config)#router rip
R1(config-router)# version 2

R2(config)#router rip
R2(config-router)# version 2

R3(config)#router rip
R3(config-router)# version 2
```
Set up on all routers.

#### Enter classful network addresses
Network 10.0.0.0 I probably always choose myself. Second network always the IP address of the interface towards the device.
```
R1(config-router)# network <10.0.0.0>
R1(config-router)# network <192.168.1.0>
R1(config-router)# no auto-summary

R2(config-router)# network <10.0.0.0>
R2(config-router)# network <209.165.200.0>
R2(config-router)# no auto-summary

R3(config-router)# network <10.0.0.0>
R3(config-router)# network <192.168.1.0>
R3(config-router)#no auto-summary
```
Set up on all routers.

#### Show
```
R1()#show ip route 
```
<br />


## HSRP
Interface towards the device. Might be a VLAN. The group number for this configuration is &lt;1&gt;. Can be more groups. Specify the priority for the router interface. The default value is &lt;100&gt;. A higher value will determine which router is the active router. If it is desirable that the active router resume that role when it becomes available again, configure it to preempt the service of the standby router. 

#### Active
```
R1(config)# interface <g0/1>
R1(config-if)# standby version 2
R1(config-if)# standby <Group number: 1> ip <IP address of virual gateway: 192.168.1.254)
R1(config-if)# standby 1 priority <150>
R1(config-if)# standby 1 preempt
```

#### Standby
```
R1(config)# interface <g0/1>
R1(config-if)# standby version 2
R1(config-if)# standby <Group number: 1> ip <IP address of virual gateway: 192.168.1.254)
```
<br />


## Port Security
#### Configure Port Security
```
S1(config)# interface range f0/1 – 2
S1(config-if-range)# switchport port-security
```
`S1(config-if-range)# switchport port-security maximum 1` - b.	Set the maximum so that only one device can access the Fast Ethernet ports
`S1(config-if-range)# switchport port-security mac-address sticky` - c.	Secure the ports so that the MAC address of a device is dynamically learned and added to the running configuration. 
`S1(config-if-range)# switchport port-security violation restrict` - d.	Set the violation mode so that the Fast Ethernet ports are not disabled when a violation occurs, but a notification of the security violation is generated and packets from the unknown source are dropped.

#### Show
```
S1# show run | begin interface
S1# show port-security
S1# show port-security address
S1# show port-security interface f0/2
```
<br />


## IPv4 Static and Default Routes
#### Default
Next hop ip address is andres of the next device interface.
```
Router(config)# ip route 0.0.0.0 0.0.0.0 <next-hop-ip-address>
```

#### Static
```
Router(config)# ip route <Destination network address> <subnet-mask> <next-hop-ip-address>
```
<br />


## IPv6 Static and Default Routes
#### Default
Next hop ip address is andres of the next device interface.
```
Router(config)# ipv6 route ::/0 {ipv6-address | exit-intf}
```
#### Static
```
ipv6 route<destination_address_and_mask> <next-hop-address> 
```
```
ipv6 route <destination_address_and_mask> <next-hop-address> <link-local-adresa>
```
