# CISCO Network Security
## OSPF
#### Enable OSPF on every router
```
R1(config)# router ospf 1
```

#### Configure the network statements
```
R1(config-router)# network 192.168.1.0 0.0.0.255 area 0
R1(config-router)# network  network 10.1.1.0 0.0.0.3 area 0
```

#### Issue the passive-interface
```
R1(config)# router ospf 1
R1(config-router)# passive-interface g0/0/1
```
set to interface to switches (not to other routers)

#### Show
```
R1# show ip ospf neighbor
R1# show ip route 
```
<br />


## OSPF Authentication using SHA256
#### Configure a key chain on all routers
```
R1(config)# key chain NetAcad 
R1(config-keychain)# key 1
```

Assign the authentication key string
```
R1(config-keychain-key)# key-string NetSeckeystring
```

Configure the encryption algorithm to be used for authentication
```
R1(config-keychain-key)# cryptographic-algorithm hmac-sha-256  
```

#### Configure  interfaces (all routers) to use OSPF authentication
```
R1(config)# interface g0/0/0 
R1(config-if)# ip ospf authentication key-chain NetAcad 
```

#### Show
```
R1# show ip ospf interface g0/0/0 
```
Must be set "Cryptographic authentication enabled Sending SA: Key 1, Algorithm HMAC-SHA-256 - key chain NetAcad"
<br />


## Static routes
#### Static default routes
(between neighbouring routes from R1-R2 and R3-R2), 10.1.1.2 - address of the connected interface (R2)
```
R1# configure terminal
R1(config)# ip route 0.0.0.0 0.0.0.0 10.1.1.2 
```

#### Static route
Static routes from R2 to the R1 outside network...
```
R2(config)# ip route [cílová síť] [maska] [next-hop IP adresa nebo výstupní rozhraní R1]
```
Be careful of the network address under the mask.
```
R2(config)# ip route 209.165.200.224 255.255.255.248 10.1.1.1
```
<br />


## Configure and Encrypt Passwords on Routers + basic settings
```
R1(config)# security passwords min-length 10
R1(config)# enable algorithm-type scrypt secret cisco12345
```

#### Configure basic console, auxiliary port
```
R1(config)# line console 0 
R1(config-line)# password ciscocon 
R1(config-line)# exec-timeout 5 0 
R1(config-line)# login 
R1(config-line)# logging synchronous 
R1(config-line)# login local 
```

```
R1(config)# line aux 0 
R1(config-line)# password ciscoauxpass 
R1(config-line)# exec-timeout 5 0 
R1(config-line)# login 
```

```
R1(config)# line vty 0 4 
R1(config-line)# password ciscovtypass 
R1(config-line)# exec-timeout 5 0 
R1(config-line)# transport input ssh
R1(config-line)# login 
```
#### Encrypt clear text passwords
```
R1(config)# service password-encryption 
```

#### Configure a login warning banner
```
R1(config)# banner motd $Unauthorized access strictly prohibited!$
```
<br />


## Configure Enhanced Username Password Security on Routers
```
R1(config)# username user01 privilege 15 algorithm-type scrypt secret user01pass 
```
<br />


## AAA Services
```
R1(config)# aaa new-model 
```

#### Implement AAA services for console access using the local database
```
R3(config)# aaa authentication login default local-case none 
```

For: Create the default login authentication method list. Use case-sensitive local authentication as the first option and the enable password as the backup option to be used if an error occurs in relation to local authentication.
```
R1(config)#aaa authentication login default local-case enable 
```

### Console
#### Configure the line console to use the defined AAA authentication method
```
R1(config)# line console 0
R1(config-line)# login authentication default
```

For: Configure the console line for privilege level 15 access on login. Set the exec-timeout value to log out after 15 minutes of inactivity. Prevent console messages from interrupting command entry.

```
R1(config)# line console 0
R1(config-line)# login authentication default
R1(config-line)# exec-timeout 15 0
R1(config-line)# logging synchronous
R1(config-line)# privilege level 15
```

### VTY
```
R1(config)# line vty 0 4
R1(config-line)# privilege level 15
R1(config-line)# exec-timeout 15 0
R1(config-line)# transport input ssh
```

#### Configure a named list AAA authentication method for the vty line
```
R1(config)# aaa authentication login SSH-LOGIN local
```

#### Configure the vty lines to use the defined AAA authentication method
```
R1(config)# line vty 0 4
R1(config-line)# login authentication SSH-LOGIN
R1(config-line)# transport input ssh
```

#### Log login activity
For: Configure the router to generate system logging messages for successful and failed login attempts. Configure the router to log every successful login. Configure the router to log every second failed login attempt.
Every two might not work.
```
R1(config)# login on-success log
R1(config)# login on-failure log every 2
```

##### Show
```
R1#show login
```
<br />


## Enable HTTP access
#### Enable the HTTP server
```
R1(config)# ip http server
```

For secure server.
```
R1(config)# ip http secure-server
```

#### Configure HTTP authentication to use the local user database
```
R1(config)# ip http authentication local
```
<br />


## SSH
```
R1(config)# ip domain-name netsec.com
R1(config)# username admin privilege 15 algorithm-type scrypt secret cisco12345 
```

```
R1(config)# line vty 0 4 
R1(config-line)# privilege level 15 
R1(config-line)# login local 
R1(config-line)# transport input ssh 
R1(config-line)# exit 
```

Erase existing key pairs on the router
```
R1(config)# crypto key zeroize rsa
```

Create new keys
```
R1(config)# crypto key generate rsa general-keys modulus 1024 
```

Issue the ip ssh version 2
```
R1(config)# ip ssh version 2 
```

#### Secure SSH
```
R1(config)# ip ssh time-out 90 
R1(config)# ip ssh authentication-retries 2 
```

#### SSH from S1 to R1
```
S1# ssh -l admin 192.168.1.1 
```

#### Show
```
R1# show ip ssh 
```
<br />


## Configure a Synchronized Time Source Using NTP
#### Set Up the NTP Master
```
R1# clock set 11:17:00 May 31 2021
```

```
R1# config t 
R1(config)# ntp authentication-key 1 md5 NTPpassword
R1(config)# ntp trusted-key 1
R1(config)# ntp authenticate
R1(config)# ntp master 3
```

#### Set Up the NTP Client
```
R2# config t 
R2(config)# ntp authentication-key 1 md5 NTPpassword
R2(config)# ntp trusted-key 1
R2(config)# ntp authenticate
R2(config)# ntp server 10.1.1.2
R2(config)# ntp update-calendar
```

#### Show
```
R2# show ntp associations
R2# show clock
```
<br />


### Configure syslog Support on R1
#### Configure R1 to log messages to the syslog server
```
R1(config)# service timestamps log datetime msec 
```

Send syslog messages to the syslog server.
```
R1(config)# logging host 192.168.1.3
```

#### Configure the logging severity level
```
R1(config)# logging trap warnings
```

#### Display the current status of logging
```
R1# show logging 
```
<br />


## Configure a ZPF
#### Create the Firewall Zones
Create an internal zone
```
R3(config)# zone security INSIDE
R3(config-sec-zone) exit
```

Create an external zone
```
R3(config-sec-zone)# zone security OUTSIDE
R3(config-sec-zone)# exit
```

#### Identify Traffic Using a Class-Map (not in practice example)
Create an ACL that defines internal traffic
```
R3(config)# access-list 101 permit ip 192.168.3.0 0.0.0.255 any
```

#### Create an inspect class-map to match the traffic ACL
```
R3(config)# class-map type inspect match-all IN-NET-CLASS-MAP
R3(config-cmap)# match access-group 101
R3(config-cmap)# match protocol tcp
R3(config-cmap)# exit
```

For: Create an inspect class-map to match the traffic to be allowed from the INSIDE zone to the OUTSIDE zone. Because we trust the INSIDE zone, we allow all the main protocols. Use the match-any keyword to instruct the router that the following match protocol statements will qualify as a successful match. This results in a policy being applied. Match for TCP, UDP, or ICMP packets.
```
R3(config)# class-map type inspect match-any INSIDE-PROTOCOLS
R3(config-cmap)# match protocol tcp
R3(config-cmap)# match protocol udp
R3(config-cmap)# match protocol icmp
```

#### Specify Firewall Policies
Create a policy map to determine what to do with matched traffic
```
R3(config)# policy-map type inspect INSIDE-TO-OUTSIDE
```

Specify a class type of inspect and reference class map IN-NET-CLASS-MAP
```
R3(config-pmap)# class type inspect INSIDE-PROTOCOLS
```

Specify the action of inspect for this policy map
```
R3(config-pmap-c)# inspect
```

#### Apply Firewall Policies
Create a pair of zones
```
R3(config)# zone-pair security INSIDE-TO-OUTSIDE source INSIDE destination OUTSIDE
```

Specify the policy map for handling the traffic between the two zones
```
R3(config-sec-zone-pair)# service-policy type inspect INSIDE-TO-OUTSIDE
```

 Assign interfaces to the appropriate security zones
```
R3(config)# interface g0/1
R3(config-if)# zone-member security INSIDE
R3(config-if)# exit
R3(config)# interface s0/0/1
R3(config-if)# zone-member security OUTSIDE
R3(config-if)# exit
```

#### Show
```
R3# show policy-map type inspect zone-pair sessions
```
<br />


## Configure IOS Intrusion Prevention System (IPS)
#### Enable IOS IPS
Create an IOS IPS configuration directory in flash
```
R1# mkdir ipsdir
```

Configure the IPS signature storage location (probably optional)
```
R1(config)# ip ips config location flash:ipsdir
```

Create an IPS rule
```
R1(config)# ip ips name iosips
```

Enable logging (probably optional)
```
R1(config)# ip ips notify log
R1# clock set 10:20:00 10 january 2014
R1(config)# service timestamps log datetime msec
R1(config)# logging host 192.168.1.50
```

Configure IOS IPS to use the signature categories
```
R1(config)# ip ips signature-category
R1(config-ips-category)# category all
R1(config-ips-category-action)# retired true
R1(config-ips-category-action)# exit
R1(config-ips-category)# category ios_ips basic
R1(config-ips-category-action)# retired false
```

Apply the IPS rule to an interface
```
R1(config)# interface g0/1
R1(config-if)# ip ips iosips in (out) 
```

#### Modify the Signature (probably optional)
```
R1(config)# ip ips signature-definition
R1(config-sigdef)# signature 2004 0
R1(config-sigdef-sig)# status
R1(config-sigdef-sig-status)# retired false
R1(config-sigdef-sig-status)# enabled true
R1(config-sigdef-sig-status)# exit
R1(config-sigdef-sig)# engine
R1(config-sigdef-sig-engine)# event-action produce-alert
R1(config-sigdef-sig-engine)# event-action deny-packet-inline
```

#### Show
```
R1 # show ip ips all
```
<br />


## Configure a Site-to-Site IPsec VPN
```
R3(config)# crypto isakmp enable
```

#### Create an ISAKMP policy with a priority number of 1
```
R3(config)# crypto isakmp policy 1
R3(config-isakmp)# authentication pre-share
R3(config-isakmp)# encryption aes 256
R3(config-isakmp)# hash sha
R3(config-isakmp)# group 2
R3(config-isakmp)# lifetime 1800
```

209.165.200.226 IP address of next router interface (R1) (PeerIP Address)
```
R3(config)# crypto isakmp key Site2SiteKEY1 address 209.165.200.226
```

#### Configure the IPsec transform set and lifetime
```
R3(config)# crypto ipsec transform-set TRNSFRM-SET esp-aes esp-sha-hmac
```

#### Define interesting traffic (Encrypted Network)
```
R3(config)# access-list 101 permit ip 172.16.3.0 0.0.0.255 192.168.1.0 0.0.0.255
```

#### Create and apply a crypto map
```
R3(config)# crypto map CMAP 1 ipsec-isakmp
R3(config-crypto-map)# match address 101
R3(config-crypto-map)# set peer 209.165.200.226
R3(config-crypto-map)# set transform-set TRNSFRM-SET
R3(config-crypto-map)# set pfs group2
R3(config-crypto-map)# set security-association lifetime seconds 1800
R3(config)# interface S0/0/1
R3(config-if)# crypto map CMAP
```

```
209.165.200.226 IP address of next router interface (R1)

```

#### Show
```
R3# show crypto isakmp policy
R3# show crypto map
R3# show crypto isakmp sa
```
</br>


## Configure Administrative Roles
#### Enable AAA on router R1.
```
R1# configure terminal 
R1(config)# aaa new-model 
```

#### Configure privileged EXEC mode password 
```
R1(config)# enable secret cisco12345 
```

#### Enable the root view
```
R1# enable view
Password: cisco12345
```

#### Create the admin1 view, establish a password, and assign privileges
```
R1(config)# parser view admin1
R1(config-view)# secret admin1pass
```

```
R1(config-view)# commands exec include all show 
R1(config-view)# commands exec include all config terminal 
R1(config-view)# commands exec include all debug
```

```
R1(config-view)# commands exec include show version 
R1(config-view)# commands exec include show interfaces 
R1(config-view)# commands exec include show ip interface brief 
R1(config-view)# commands exec include show parser view 
```

#### Verify the admin1 view 
```
R1# enable view admin1 
Password: admin1pass
```

#### Show
```
R1# show parser view 
```
<br />


## Configure Automated Security Features 
```
R1# auto secure 
```
<br />



## SNMPv3 Security using an ACL
#### Configure an ACL
```
R1(config)# ip access-list standard PERMIT-SNMP
```

Add a permit statement to allow only packets on R1’s LAN. 
```
R1(config-std-nacl)# permit 192.168.1.0 0.0.0.255 
```

#### Configure the SNMP view
```
R1(config)# snmp-server view SNMP-RO iso included 
```

#### Configure the SNMP group
```
R1(config)# snmp-server group SNMP-G1 v3 priv read SNMP-RO access PERMIT-SNMP 
```

#### Configure the SNMP user
```
R1(config)# snmp-server user SNMP-Admin SNMP-G1 v3 auth sha Authpass priv aes 128 Encrypass  
```

#### Show
```
R1# show snmp group  
```
Must be set "groupname: SNMP-G1, readview : SNMP-RO, security model:v3 priv, access-list: PERMIT-SNMP"

```
R1# show snmp user 
```
Must be set "User name: SNMP-Admin, Authentication Protocol: SHA, Privacy Protocol: AES128, Group-name: SNMP-G1"
<br />


## Configure Local Authentication Using AAA (Enable AAA services)
#### Configure the local user database
```
R3(config)# username Admin01 privilege 15 algorithm-type sha256 secret Admin01pass 
```

#### Enable AAA services
```
R3(config)# aaa new-model 
```

#### Implement AAA services for console access using the local database
```
R3(config)# aaa authentication login default local-case none 
```

For: Create the default login authentication method list. Use case-sensitive local authentication as the first option and the enable password as the backup option to be used if an error occurs in relation to local authentication.
```
R1(config)#aaa authentication login default local-case enable 
```


#### Create an AAA authentication profile for SSH using the local database
```
R3(config)# aaa authentication login SSH_LINES local 
R3(config)# line vty 0 4
R3(config-line)# login authentication SSH_LINES
```
<br />


## Configure Server-Based Authentication with RADIUS
```
R1(config)# aaa new-model 
```

#### Configure the default login authentication method list
```
R1(config)# aaa authentication login default group radius none 
```

#### Specify a RADIUS server
```
R1(config)# radius server NetSec 
R1(config-radius-server)# address ipv4 192.168.1.11 
R1(config-radius-server)# key $trongPass
```

#### Change the RADIUS port numbers
```
R1(config)# radius server NetSec 
R1(config-radius-server)# address ipv4 192.168.1.11 auth-port 1812 acct-port 1813
```

#### Show
```
R1# show radius server-group radius 
```
<br />


## Configure Named Standard IPv4 ACLs
#### Configure a named standard ACL
```
R1(config)# ip access-list standard File_Server_Restrictions
R1(config-std-nacl)# permit host 192.168.20.4
R1(config-std-nacl)# deny any
```

#### Apply the named ACL
```
R1(config)# interface f0/1
R1(config-if)# ip access-group File_Server_Restrictions out
```

#### Show
```
R1# show access-lists
```
<br />


## Configure Numbered Standard IPv4 ACLs 
#### Configure a numbered standard ACL
```
R2(config)# access-list 1 deny 192.168.11.0 0.0.0.255
R2(config)# access-list 1 permit any
```

#### Apply the numbered ACL
```
R2(config)# interface GigabitEthernet0/0
R2(config-if)# ip access-group 1 out
```

#### Show
```
R2# show access-lists
```
<br />


## Configure Extended numered IPv4 ACLs
#### Configure an ACL to permit FTP and ICMP from PC1 LAN
Use ? to get help on editing the command
```
R1(config)# access-list 100 permit tcp 172.22.34.64 0.0.0.31 host 172.22.34.62 eq ftp
```

```
R1(config)# access-list 100 permit icmp 172.22.34.64 0.0.0.31 host 172.22.34.62
```

#### Apply the numbered ACL
```
R1(config)# interface gigabitEthernet 0/0
R1(config-if)# ip access-group 100 in
```

#### Show
```
R1# show access-lists
```
<br />


## Configure Extended Named IPv4 ACLs
#### Configure an ACL to permit HTTP access and ICMP from PC2 LAN
Use ? to get help on editing the command
```
R1(config)# ip access-list extended HTTP_ONLY
R1(config-ext–nacl)# permit tcp 172.22.34.96 0.0.0.15 host 172.22.34.62 eq www
R1(config-ext-nacl)# permit icmp 172.22.34.96 0.0.0.15 host 172.22.34.62
```

#### Apply the named ACL
```
R1(config)# interface gigabitEthernet 0/1
R1(config-if)# ip access-group HTTP_ONLY in
```

#### Show
```
R1# show access-lists
```
<br />


## Configure IPv6 ACLs
#### Configure an ACL that will block HTTP and HTTPS access
Use ? to get help on editing the command
```
R1(config)# ipv6 access-list BLOCK_HTTP
R1(config)# deny tcp any host 2001:db8:1:30::30 eq www
R1(config)# deny tcp any host 2001:db8:1:30::30 eq 443
```

```
R1(config)# ipv6 access-list BLOCK_ICMP
R1(config)# deny icmp any any
```

Allow all other IPv6 traffic to pass
```
R1(config)# permit ipv6 any any
```

#### Apply the named ACL
```
R1(config)# interface GigabitEthernet0/1
R1(config-if)# ipv6 traffic-filter BLOCK_HTTP in
```
<br />


## Implement a Local SPAN
#### Configure SPAN on S1
Now all traffic entering or leaving F0/5 will be copied and forwarded out of F0/6
```
S1(config)# monitor session 1 source interface f0/5
S1(config)# monitor session 1 destination interface f0/6
```
<br />


## Port Security SWITCH
#### Configure Port Security
```
S1(config)# interface range f0/1 – 2
S1(config-if-range)# switchport port-security
```

Only one device can connect to the Fast Ethernet ports 0/1 and 0/2
```
S1(config-if-range)# switchport port-security maximum 1
```

```
S1(config-if-range)# switchport port-security mac-address sticky
```

Set the violation mode so that the Fast Ethernet ports 0/1 and 0/2 are not disabled when a violation occurs
```
S1(config-if-range)# switchport port-security violation restrict
```

Disable trunking on port F0/6
```
S1(config)# interface FastEthernet 0/6
S1(config-if)# switchport mode acces
```

#### Show
```
S1# show port-security
S1# show port-security address
S1# show port-security interface f0/2
```
<br />


## STP Security SWITCH
#### Configure Root Bridge
```
Central(config)# spanning-tree vlan 1 root primary
```

#### Assign SW-1 as a secondary root bridge
```
SW-1(config)# spanning-tree vlan 1 root secondary
```

#### Protect Against STP Attacks
Enable PortFast on all access ports
```
SW-A(config)# interface range f0/1 – 4
SW-A(config-if-range)# spanning-tree portfast
```

Enable BPDU guard on all access ports
```
SW-A(config)# interface range f0/1 – 4
SW-A(config-if-range)# spanning-tree bpduguard enable
```

Enable root guard can be enabled on all ports on a switch that are not root ports
```
SW-1(config)# interface range f0/23 – 24
SW-1(config-if-range)# spanning-tree guard root
```

Set loop guard as the default for all non-designated ports on S1
```
S1(config)# spanning-tree loopguard default
```

#### Show
```
Central# show spanning-tree
```
<br />


## VLAN Security SWITCH
#### Create a Redundant Link Between SW-1 and SW-2
```
SW-1(config)# interface f0/23
SW-1(config-if)# switchport mode trunk
SW-1(config-if)# switchport trunk native vlan 15
SW-1(config-if)# switchport nonegotiate
SW-1(config-if)# no shutdown
SW-2(config)# interface f0/23
SW-2(config-if)# switchport mode trunk
SW-2(config-if)# switchport trunk native vlan 15
SW-2(config-if)# switchport nonegotiate
SW-2(config-if)# no shutdown
```

#### Enable VLAN 20 as a Management VLAN
```
SW-A(config)# vlan 20
SW-A(config-vlan)# exit
SW-A(config)# interface vlan 20
SW-A(config-if)# ip address 192.168.20.1 255.255.255.0
```

```
SW-A(config)# interface f0/1
SW-A(config-if)# switchport access vlan 20
SW-A(config-if)# no shutdown
```

#### Enable a new subinterface on router R1
```
R1(config)# interface g0/0.3
R1(config-subif)# encapsulation dot1q 20
R1(config)# interface g0/0.3
R1(config-subif)# ip address 192.168.20.100 255.255.255.0
```

#### Enable security
Create an ACL that allows only the Management PC to access the router
```
R1(config)# access-list 101 deny ip any 192.168.20.0 0.0.0.255
R1(config)# access-list 101 permit ip any any
R1(config)# access-list 102 permit ip host 192.168.20.50 any
```

Apply the ACL
```
R1(config)# interface g0/0.1
R1(config-subif)# ip access-group 101 in
R1(config-subif)# line vty 0 4
R1(config-line)# access-class 102 in
```
<br />


## Secure against Login Attacks and Secure the IOS and Configuration File
#### Configure enhanced login security
```
R1(config)# login block-for 60 attempts 2 within 30
R1(config)# login on-failure log
```

#### Secure the Cisco IOS image and archive a copy of the running configu
```
R1(config)# secure boot-image
```

```
R1(config)# secure boot-config
```

#### Show
```
R1# show secure bootset
```
<br />


## Licence
#### Security licence 
```
R3(config)#license boot module c1900 technology-package securityk9
```
```
R1# reload
```

#### Show
```
R1# show version
```
<br />


## DHCP
```
dhcpd address 192.168.10.25-192.168.10.35 INSIDE
dhcpd dns 192.168.10.10 interface INSIDE
dhcpd option 3 ip 192.168.10.1
dhcpd enable INSIDE
```
