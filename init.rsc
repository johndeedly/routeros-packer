:put ":: configure system";
:do {
    /system clock set time-zone-name=CET;
    /ip service set telnet disabled=yes;
    /ip service set winbox disabled=yes;
    /ip dns set servers=94.140.14.14,94.140.15.15;
    /system ntp server set enabled=yes use-local-clock=yes;
} on-error={ :put "!! error configuring system"; };

:put ":: enable self-signed ssl access";
:do {
    :put " - ca certificate";
    /certificate add name=LocalCA common-name=LocalCA days-valid=36500 key-usage=key-cert-sign,crl-sign;
    /certificate sign LocalCA;
    :put " - webfig certificate";
    /certificate add name=self-signed common-name=self-signed days-valid=36500;
    /certificate sign self-signed ca=LocalCA;
    :put " - enable www-ssl";
    /ip service set www-ssl certificate=self-signed disabled=no;
    :put " - enable api-ssl";
    /ip service set api-ssl certificate=self-signed disabled=no;
} on-error={ :put "!! error enabling self-signed ssl access"; };

:put ":: configure default network";
:do {
    :put " - additional wan port for load balancing";
    /interface macvlan add name=wan2 mode=private interface=ether1;

    :put " - create bridge brlan1";
    /interface bridge add name=brlan1 comment="main lan bridge: vlan 16 users, 32 guests" frame-types=admit-only-vlan-tagged;
    /interface bridge port add bridge=brlan1 interface=lan1 pvid=16 frame-types=admit-only-untagged-and-priority-tagged;
    /interface bridge vlan add bridge=brlan1 tagged=brlan1 vlan-ids=16,32;
    
    :put " - connect users and guests to brlan1";
    /interface vlan add interface=brlan1 vlan-id=16 name=user1;
    /interface vlan add interface=brlan1 vlan-id=32 name=guest1;
    
    :put " - enable vlan filtering on brlan1";
    /interface bridge set brlan1 vlan-filtering=yes;

    :put " - dhcpv4 client on wan ports";
    /routing table add disabled=no fib name=wan1_table_ipv4;
    /ip route add check-gateway=ping disabled=yes dst-address=0.0.0.0/0 gateway=0.0.0.0 distance=1 routing-table=wan1_table_ipv4 suppress-hw-offload=no comment="wan1 dhcp script #1";
    /ip route add check-gateway=ping disabled=yes dst-address=0.0.0.0/0 gateway=0.0.0.0 distance=1 suppress-hw-offload=no comment="wan1 dhcp script #2";
    /ip dhcp-client add disabled=yes interface=wan1 script=\
        ":if (\$bound=1) do={\
        \n  :local routeID [/ip route find comment=\"wan1 dhcp script #1\"];\
        \n  if ([/ip route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ip route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n  :local routeID [/ip route find comment=\"wan1 dhcp script #2\"];\
        \n  if ([/ip route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ip route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n};" add-default-route=no use-peer-dns=no use-peer-ntp=no;
    /routing table add disabled=no fib name=wan2_table_ipv4;
    /ip route add check-gateway=ping disabled=yes dst-address=0.0.0.0/0 gateway=0.0.0.0 distance=1 routing-table=wan2_table_ipv4 suppress-hw-offload=no comment="wan2 dhcp script #1";
    /ip route add check-gateway=ping disabled=yes dst-address=0.0.0.0/0 gateway=0.0.0.0 distance=2 suppress-hw-offload=no comment="wan2 dhcp script #2";
    /ip dhcp-client add disabled=yes interface=wan2 script=\
        ":if (\$bound=1) do={\
        \n  :local routeID [/ip route find comment=\"wan2 dhcp script #1\"];\
        \n  if ([/ip route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ip route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n  :local routeID [/ip route find comment=\"wan2 dhcp script #2\"];\
        \n  if ([/ip route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ip route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n};" add-default-route=no use-peer-dns=no use-peer-ntp=no;
    
    :put " - dhcpv6 client on wan ports";
    /routing table add disabled=no fib name=wan1_table_ipv6;
    /ipv6 route add check-gateway=ping disabled=yes dst-address=::/0 gateway=:: distance=1 routing-table=wan1_table_ipv6 suppress-hw-offload=no comment="wan1 dhcp script #1";
    /ipv6 route add check-gateway=ping disabled=yes dst-address=::/0 gateway=:: distance=1 suppress-hw-offload=no comment="wan1 dhcp script #2";
    /ipv6 dhcp-client add disabled=yes interface=wan1 script=\
        ":if (\$bound=1) do={\
        \n  :local routeID [/ipv6 route find comment=\"wan1 dhcp script #1\"];\
        \n  if ([/ipv6 route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ipv6 route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n  :local routeID [/ipv6 route find comment=\"wan1 dhcp script #2\"];\
        \n  if ([/ipv6 route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ipv6 route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n};" add-default-route=no use-peer-dns=no pool-name=TPP2-v6 request=address;
    /routing table add disabled=no fib name=wan2_table_ipv6;
    /ipv6 route add check-gateway=ping disabled=yes dst-address=::/0 gateway=:: distance=1 routing-table=wan2_table_ipv6 suppress-hw-offload=no comment="wan2 dhcp script #1";
    /ipv6 route add check-gateway=ping disabled=yes dst-address=::/0 gateway=:: distance=2 suppress-hw-offload=no comment="wan2 dhcp script #2";
    /ipv6 dhcp-client add disabled=yes interface=wan2 script=\
        ":if (\$bound=1) do={\
        \n  :local routeID [/ipv6 route find comment=\"wan2 dhcp script #1\"];\
        \n  if ([/ipv6 route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ipv6 route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n  :local routeID [/ipv6 route find comment=\"wan2 dhcp script #2\"];\
        \n  if ([/ipv6 route get \$routeID gateway] != \$\"gateway-address\") do={\
        \n    /ipv6 route set \$routeID disabled=no gateway=\$\"gateway-address\";\
        \n  };\
        \n};" add-default-route=no use-peer-dns=no pool-name=TPP3-v6 request=address;
    
    :put " - dhcpv4 server on user1 and guest1";
    /ip pool add name=user1-pool ranges=192.168.88.10-192.168.88.254;
    /ip pool add name=guest1-pool ranges=192.168.99.10-192.168.99.254;
    /ip dhcp-server network add address=192.168.88.0/24 dns-server=192.168.88.1 ntp-server=192.168.88.1 gateway=192.168.88.1;
    /ip dhcp-server network add address=192.168.99.0/24 dns-server=192.168.99.1 ntp-server=192.168.99.1 gateway=192.168.99.1;
    /ip address add address=192.168.88.1/24 interface=user1 network=192.168.88.0;
    /ip address add address=192.168.99.1/24 interface=guest1 network=192.168.99.0;
    /ip dhcp-server add address-pool=user1-pool disabled=no interface=user1 name=user1-dhcp;
    /ip dhcp-server add address-pool=guest1-pool disabled=no interface=guest1 name guest1-dhcp;

    :put " - dhcpv6 server on user1 and guest1";
    /ipv6 pool add name=user1-pool-ipv6 prefix=fdee:2eae:0520::/48 prefix-length=64;
    /ipv6 pool add name=guest1-pool-ipv6 prefix=fd3d:559b:ff6c::/48 prefix-length=64;
    /ipv6 dhcp-server add name=user1-dhcp-ipv6 address-pool=user1-pool-ipv6 interface=user1;
    /ipv6 dhcp-server add name=guest1-dhcp-ipv6 address-pool=guest1-pool-ipv6 interface=guest1;
} on-error={ :put "!! error configuring default network"; };

:put ":: vpn server settings";
:do {
    :put " - create wireguard server";
    /interface wireguard add listen-port=51820 mtu=1380 name=wg1;
    /interface wireguard peers add allowed-address=172.21.0.0/30 endpoint-address=0.0.0.0 endpoint-port=51820 interface=wg1 name=peer1 persistent-keepalive=25s public-key="VmGMh+cwPdb8//NOhuf1i1VIThypkMQrKAO9Y55ghG8=";
    /ip address add address=172.21.0.1/30 interface=wg1 network=172.21.0.0;

    :put " - wireguard server summary";
    /interface wireguard print;
} on-error={ :put "!! error configuring vpn server settings"; };

# https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall
:put ":: basic firewall rules";
:do {
    :put " - create interface lists";
    /interface list add name=WAN;
    /interface list add name=LAN;
    /interface list add name=USER;
    /interface list add name=GUEST;
    /interface list add name=MGMT;
    /interface list add name=VPN;
    /interface list member add interface=wan1 list=WAN;
    /interface list member add interface=wan2 list=WAN;
    /interface list member add interface=lan1 list=LAN;
    /interface list member add interface=brlan1 list=LAN;
    /interface list member add interface=user1 list=LAN;
    /interface list member add interface=guest1 list=LAN;
    /interface list member add interface=user1 list=USER;
    /interface list member add interface=guest1 list=GUEST;
    /interface list member add interface=mgmt1 list=MGMT;
    /interface list member add interface=wg1 list=VPN;
    
    :put " - add ipv4 rules to protect the mikrotik itself";
    /ip firewall filter add action=accept chain=input comment="accept ICMP after RAW" protocol=icmp;
    /ip firewall filter add action=accept chain=input comment="accept established,related,untracked" connection-state=established,related,untracked;
    /ip firewall filter add action=accept chain=input comment="accept wireguard server traffic" dst-port=51820 protocol=udp;
    /ip firewall filter add action=drop chain=input comment="drop services not coming from MGMT" protocol=tcp dst-port=21,22,23,80,443,8291,8728,8729 in-interface-list=!MGMT;
    /ip firewall filter add action=drop chain=input comment="drop services not coming from MGMT" protocol=udp dst-port=21,22,23,80,443,8291,8728,8729 in-interface-list=!MGMT;
    /ip firewall filter add action=drop chain=input comment="drop all coming from WAN" in-interface-list=WAN;

    :put " - add ipv6 rules to protect the mikrotik itself";
    /ipv6 firewall filter add action=accept chain=input comment="accept ICMPv6 after RAW" protocol=icmpv6;
    /ipv6 firewall filter add action=accept chain=input comment="accept established,related,untracked" connection-state=established,related,untracked;
    /ipv6 firewall filter add action=accept chain=input comment="accept UDP traceroute" dst-port=33434-33534 protocol=udp;
    /ipv6 firewall filter add action=accept chain=input comment="accept DHCPv6-Client prefix delegation" dst-port=546 protocol=udp src-address=fe80::/10;
    /ipv6 firewall filter add action=accept chain=input comment="accept IKE" dst-port=500,4500 protocol=udp;
    /ipv6 firewall filter add action=accept chain=input comment="accept IPSec AH" protocol=ipsec-ah;
    /ipv6 firewall filter add action=accept chain=input comment="accept IPSec ESP" protocol=ipsec-esp;
    /ipv6 firewall filter add action=accept chain=input comment="accept wireguard server traffic" dst-port=51820 protocol=udp;
    /ipv6 firewall filter add action=drop chain=input comment="drop services not coming from MGMT" protocol=tcp dst-port=21,22,23,80,443,8291,8728,8729 in-interface-list=!MGMT;
    /ipv6 firewall filter add action=drop chain=input comment="drop services not coming from MGMT" protocol=udp dst-port=21,22,23,80,443,8291,8728,8729 in-interface-list=!MGMT;
    /ipv6 firewall filter add action=drop chain=input comment="drop all coming from WAN" in-interface-list=WAN;

    :put " - redirect external dns ipv4";
    /ip firewall nat add chain=dstnat action=dst-nat to-addresses=192.168.88.1 to-ports=53 protocol=udp dst-address=!192.168.88.1 in-interface-list=LAN dst-port=53;
    /ip firewall nat add chain=dstnat action=dst-nat to-addresses=192.168.88.1 to-ports=53 protocol=tcp dst-address=!192.168.88.1 in-interface-list=LAN dst-port=53;
    /ip firewall nat add chain=dstnat action=dst-nat to-addresses=192.168.99.1 to-ports=53 protocol=udp dst-address=!192.168.99.1 in-interface-list=LAN dst-port=53;
    /ip firewall nat add chain=dstnat action=dst-nat to-addresses=192.168.99.1 to-ports=53 protocol=tcp dst-address=!192.168.99.1 in-interface-list=LAN dst-port=53;

    :put " - create no-forward ipv4 address lists";
    /ip firewall address-list add address=0.0.0.0/8 comment="RFC6890" list=no_forward_ipv4;
    /ip firewall address-list add address=169.254.0.0/16 comment="RFC6890" list=no_forward_ipv4;
    /ip firewall address-list add address=224.0.0.0/4 comment="multicast" list=no_forward_ipv4;
    /ip firewall address-list add address=255.255.255.255/32 comment="RFC6890" list=no_forward_ipv4;
    
    :put " - create no-forward ipv6 address lists";
    /ipv6 firewall address-list add address=fe80::/10 comment="RFC6890 Linked-Scoped Unicast" list=no_forward_ipv6;
    /ipv6 firewall address-list add address=ff00::/8 comment="multicast" list=no_forward_ipv6;
    
    :put " - protect the clients ipv4";
    /ip firewall filter add action=accept chain=forward comment="accept all that matches IPSec policy" ipsec-policy=in,ipsec disabled=yes;
    /ip firewall filter add action=fasttrack-connection chain=forward comment="fasttrack" connection-state=established,related;
    /ip firewall filter add action=accept chain=forward comment="accept established,related, untracked" connection-state=established,related,untracked;
    /ip firewall filter add action=drop chain=forward comment="drop invalid" connection-state=invalid;
    /ip firewall filter add action=drop chain=forward comment="drop all from WAN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN;
    /ip firewall filter add action=drop chain=forward comment="drop all from VPN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=VPN;
    /ip firewall filter add action=drop chain=forward comment="drop all from GUEST not forwarding to WAN (guest client isolation)" connection-state=new in-interface-list=GUEST out-interface-list=!WAN;
    /ip firewall filter add action=drop chain=forward src-address-list=no_forward_ipv4 comment="drop bad forward IPs";
    /ip firewall filter add action=drop chain=forward dst-address-list=no_forward_ipv4 comment="drop bad forward IPs";
    
    :put " - protect the clients ipv6";
    /ipv6 firewall filter add action=accept chain=forward comment="accept established,related,untracked" connection-state=established,related,untracked;
    /ipv6 firewall filter add action=drop chain=forward comment="drop invalid" connection-state=invalid;
    /ipv6 firewall filter add action=drop chain=forward src-address-list=no_forward_ipv6 comment="drop bad forward IPs";
    /ipv6 firewall filter add action=drop chain=forward dst-address-list=no_forward_ipv6 comment="drop bad forward IPs";
    /ipv6 firewall filter add action=drop chain=forward comment="rfc4890 drop hop-limit=1" hop-limit=equal:1 protocol=icmpv6;
    /ipv6 firewall filter add action=accept chain=forward comment="accept ICMPv6 after RAW" protocol=icmpv6;
    /ipv6 firewall filter add action=accept chain=forward comment="accept HIP" protocol=139;
    /ipv6 firewall filter add action=accept chain=forward comment="accept IKE" protocol=udp dst-port=500,4500;
    /ipv6 firewall filter add action=accept chain=forward comment="accept AH" protocol=ipsec-ah;
    /ipv6 firewall filter add action=accept chain=forward comment="accept ESP" protocol=ipsec-esp;
    /ipv6 firewall filter add action=accept chain=forward comment="accept all that matches IPSec policy" ipsec-policy=in,ipsec;
    /ipv6 firewall filter add action=drop chain=forward comment="drop all from WAN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=WAN;
    /ipv6 firewall filter add action=drop chain=forward comment="drop all from VPN not DSTNATed" connection-nat-state=!dstnat connection-state=new in-interface-list=VPN;
    /ipv6 firewall filter add action=drop chain=forward comment="drop all from GUEST not forwarding to WAN (guest client isolation)" connection-state=new in-interface-list=GUEST out-interface-list=!WAN;
    /ipv6 firewall filter add action=drop chain=forward comment="drop everything else coming from WAN" in-interface-list=WAN;
    
    :put " - masquerade local network ipv4";
    /ip firewall nat add action=accept chain=srcnat comment="accept all that matches IPSec policy" ipsec-policy=out,ipsec disabled=yes;
    /ip firewall nat add action=masquerade chain=srcnat comment="masquerade WAN" out-interface-list=WAN;
    /ip firewall nat add action=masquerade chain=srcnat comment="masquerade VPN" out-interface-list=VPN;
    
    :put " - masquerade local network ipv6";
    /ipv6 firewall nat add action=accept chain=srcnat comment="accept all that matches IPSec policy" ipsec-policy=out,ipsec disabled=yes;
    /ipv6 firewall nat add action=masquerade chain=srcnat comment="masquerade WAN" out-interface-list=WAN;
    /ipv6 firewall nat add action=masquerade chain=srcnat comment="masquerade VPN" out-interface-list=VPN;
    
    :put " - create bad ipv4 address lists";
    /ip firewall address-list add address=127.0.0.0/8 comment="RFC6890" list=bad_ipv4;
    /ip firewall address-list add address=192.0.0.0/24 comment="RFC6890" list=bad_ipv4;
    /ip firewall address-list add address=192.0.2.0/24 comment="RFC6890 documentation" list=bad_ipv4;
    /ip firewall address-list add address=198.51.100.0/24 comment="RFC6890 documentation" list=bad_ipv4;
    /ip firewall address-list add address=203.0.113.0/24 comment="RFC6890 documentation" list=bad_ipv4;
    /ip firewall address-list add address=240.0.0.0/4 comment="RFC6890 reserved" list=bad_ipv4;
    
    /ip firewall address-list add address=0.0.0.0/8 comment="RFC6890" list=not_global_ipv4;
    /ip firewall address-list add address=10.0.0.0/8 comment="RFC6890" list=not_global_ipv4;
    /ip firewall address-list add address=100.64.0.0/10 comment="RFC6890" list=not_global_ipv4;
    /ip firewall address-list add address=169.254.0.0/16 comment="RFC6890" list=not_global_ipv4;
    /ip firewall address-list add address=172.16.0.0/12 comment="RFC6890" list=not_global_ipv4;
    /ip firewall address-list add address=192.0.0.0/29 comment="RFC6890" list=not_global_ipv4;
    /ip firewall address-list add address=192.168.0.0/16 comment="RFC6890" list=not_global_ipv4;
    /ip firewall address-list add address=198.18.0.0/15 comment="RFC6890 benchmark" list=not_global_ipv4;
    /ip firewall address-list add address=255.255.255.255/32 comment="RFC6890" list=not_global_ipv4;
    
    /ip firewall address-list add address=224.0.0.0/4 comment="multicast" list=bad_src_ipv4;
    /ip firewall address-list add address=255.255.255.255/32 comment="RFC6890" list=bad_src_ipv4;
    /ip firewall address-list add address=0.0.0.0/8 comment="RFC6890" list=bad_dst_ipv4;
    /ip firewall address-list add address=224.0.0.0/4 comment="RFC6890" list=bad_dst_ipv4;
    
    :put " - raw filters ipv4";
    /ip firewall raw add action=accept chain=prerouting comment="enable for transparent firewall" disabled=yes;
    /ip firewall raw add action=accept chain=prerouting comment="accept DHCP discover" dst-address=255.255.255.255 dst-port=67 in-interface-list=LAN protocol=udp src-address=0.0.0.0 src-port=68;
    /ip firewall raw add action=drop chain=prerouting comment="drop bogon IP's" src-address-list=bad_ipv4;
    /ip firewall raw add action=drop chain=prerouting comment="drop bogon IP's" dst-address-list=bad_ipv4;
    /ip firewall raw add action=drop chain=prerouting comment="drop bogon IP's" src-address-list=bad_src_ipv4;
    /ip firewall raw add action=drop chain=prerouting comment="drop bogon IP's" dst-address-list=bad_dst_ipv4;
    /ip firewall raw add action=drop chain=prerouting comment="drop non global from WAN" src-address-list=not_global_ipv4 in-interface-list=WAN;
    /ip firewall raw add action=drop chain=prerouting comment="drop forward to local lan from WAN" in-interface-list=WAN dst-address=192.168.0.0/16;
    /ip firewall raw add action=drop chain=prerouting comment="drop local if not from default IP range" in-interface-list=LAN src-address=!192.168.0.0/16;
    /ip firewall raw add action=drop chain=prerouting comment="drop bad UDP" port=0 protocol=udp;
    /ip firewall raw add action=jump chain=prerouting comment="jump to ICMP chain" jump-target=icmp4 protocol=icmp;
    /ip firewall raw add action=jump chain=prerouting comment="jump to TCP chain" jump-target=bad_tcp protocol=tcp;
    /ip firewall raw add action=accept chain=prerouting comment="accept everything else from WAN" in-interface-list=WAN;
    /ip firewall raw add action=accept chain=prerouting comment="accept everything else from LAN" in-interface-list=LAN;
    /ip firewall raw add action=accept chain=prerouting comment="accept everything else from MGMT" in-interface-list=MGMT;
    /ip firewall raw add action=accept chain=prerouting comment="accept everything else from VPN" in-interface-list=VPN;
    /ip firewall raw add action=drop chain=prerouting comment="drop the rest";
    
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP flag filter" protocol=tcp tcp-flags=!fin,!syn,!rst,!ack;
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP flag filter" protocol=tcp tcp-flags=fin,syn;
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP flag filter" protocol=tcp tcp-flags=fin,rst;
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP flag filter" protocol=tcp tcp-flags=fin,!ack;
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP flag filter" protocol=tcp tcp-flags=fin,urg;
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP flag filter" protocol=tcp tcp-flags=syn,rst;
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP flag filter" protocol=tcp tcp-flags=rst,urg;
    /ip firewall raw add action=drop chain=bad_tcp comment="TCP port 0 drop" port=0 protocol=tcp;
    
    /ip firewall raw add action=accept chain=icmp4 comment="echo reply" icmp-options=0:0 limit=5,10:packet protocol=icmp;
    /ip firewall raw add action=accept chain=icmp4 comment="net unreachable" icmp-options=3:0 protocol=icmp;
    /ip firewall raw add action=accept chain=icmp4 comment="host unreachable" icmp-options=3:1 protocol=icmp;
    /ip firewall raw add action=accept chain=icmp4 comment="protocol unreachable" icmp-options=3:2 protocol=icmp;
    /ip firewall raw add action=accept chain=icmp4 comment="port unreachable" icmp-options=3:3 protocol=icmp;
    /ip firewall raw add action=accept chain=icmp4 comment="fragmentation needed" icmp-options=3:4 protocol=icmp;
    /ip firewall raw add action=accept chain=icmp4 comment="echo" icmp-options=8:0 limit=5,10:packet protocol=icmp;
    /ip firewall raw add action=accept chain=icmp4 comment="time exceeded " icmp-options=11:0-255 protocol=icmp;
    /ip firewall raw add action=drop chain=icmp4 comment="drop other icmp" protocol=icmp;
    
    :put " - create bad ipv6 address lists";
    /ipv6 firewall address-list add address=::1/128 comment="RFC6890 lo" list=bad_ipv6;
    /ipv6 firewall address-list add address=::ffff:0:0/96 comment="RFC6890 IPv4 mapped" list=bad_ipv6;
    /ipv6 firewall address-list add address=2001::/23 comment="RFC6890" list=bad_ipv6;
    /ipv6 firewall address-list add address=2001:db8::/32 comment="RFC6890 documentation" list=bad_ipv6;
    /ipv6 firewall address-list add address=2001:10::/28 comment="RFC6890 orchid" list=bad_ipv6;
    /ipv6 firewall address-list add address=::/96 comment="ipv4 compat" list=bad_ipv6;
    
    /ipv6 firewall address-list add address=100::/64 comment="RFC6890 Discard-only" list=not_global_ipv6;
    /ipv6 firewall address-list add address=2001::/32 comment="RFC6890 TEREDO" list=not_global_ipv6;
    /ipv6 firewall address-list add address=2001:2::/48 comment="RFC6890 Benchmark" list=not_global_ipv6;
    /ipv6 firewall address-list add address=fc00::/7 comment="RFC6890 Unique-Local" list=not_global_ipv6;
    
    /ipv6 firewall address-list add address=::/128 comment="unspecified" list=bad_dst_ipv6;
    
    /ipv6 firewall address-list add address=::/128 comment="unspecified" list=bad_src_ipv6;
    /ipv6 firewall address-list add address=ff00::/8  comment="multicast" list=bad_src_ipv6;
    
    :put " - raw filters ipv6";
    /ipv6 firewall raw add action=accept chain=prerouting comment="enable for transparent firewall" disabled=yes;
    /ipv6 firewall raw add action=accept chain=prerouting comment="RFC4291, section 2.7.1" src-address=::/128 dst-address=ff02:0:0:0:0:1:ff00::/104 icmp-options=135 protocol=icmpv6;
    /ipv6 firewall raw add action=drop chain=prerouting comment="drop bogon IP's" src-address-list=bad_ipv6;
    /ipv6 firewall raw add action=drop chain=prerouting comment="drop bogon IP's" dst-address-list=bad_ipv6;
    /ipv6 firewall raw add action=drop chain=prerouting comment="drop packets with bad SRC ipv6" src-address-list=bad_src_ipv6;
    /ipv6 firewall raw add action=drop chain=prerouting comment="drop packets with bad dst ipv6" dst-address-list=bad_dst_ipv6;
    /ipv6 firewall raw add action=drop chain=prerouting comment="drop non global from WAN" src-address-list=not_global_ipv6 in-interface-list=WAN;
    /ipv6 firewall raw add action=jump chain=prerouting comment="jump to ICMPv6 chain" jump-target=icmp6 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=prerouting comment="accept local multicast scope" dst-address=ff02::/16;
    /ipv6 firewall raw add action=drop chain=prerouting comment="drop other multicast destinations" dst-address=ff00::/8;
    /ipv6 firewall raw add action=accept chain=prerouting comment="accept everything else from WAN" in-interface-list=WAN;
    /ipv6 firewall raw add action=accept chain=prerouting comment="accept everything else from LAN" in-interface-list=LAN;
    /ipv6 firewall raw add action=accept chain=prerouting comment="accept everything else from MGMT" in-interface-list=MGMT;
    /ipv6 firewall raw add action=accept chain=prerouting comment="accept everything else from VPN" in-interface-list=VPN;
    /ipv6 firewall raw add action=drop chain=prerouting comment="drop the rest";
    
    /ipv6 firewall raw add action=drop chain=icmp6 comment="rfc4890 drop ll if hop-limit!=255" dst-address=fe80::/10 hop-limit=not-equal:255 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="dst unreachable" icmp-options=1:0-255 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="packet too big" icmp-options=2:0-255 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="limit exceeded" icmp-options=3:0-1 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="bad header" icmp-options=4:0-2 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="Mobile home agent address discovery" icmp-options=144:0-255 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="Mobile home agent address discovery" icmp-options=145:0-255 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="Mobile prefix solic" icmp-options=146:0-255 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="Mobile prefix advert" icmp-options=147:0-255 protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="echo request limit 5,10" icmp-options=128:0-255 limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="echo reply limit 5,10" icmp-options=129:0-255 limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="rfc4890 router solic limit 5,10 only LAN" hop-limit=equal:255 icmp-options=133:0-255 in-interface-list=LAN limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="rfc4890 router advert limit 5,10 only LAN" hop-limit=equal:255 icmp-options=134:0-255 in-interface-list=LAN limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="rfc4890 neighbor solic limit 5,10 only LAN" hop-limit=equal:255 icmp-options=135:0-255 in-interface-list=LAN limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="rfc4890 neighbor advert limit 5,10 only LAN" hop-limit=equal:255 icmp-options=136:0-255 in-interface-list=LAN limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="rfc4890 inverse ND solic limit 5,10 only LAN" hop-limit=equal:255 icmp-options=141:0-255 in-interface-list=LAN limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=accept chain=icmp6 comment="rfc4890 inverse ND advert limit 5,10 only LAN" hop-limit=equal:255 icmp-options=142:0-255 in-interface-list=LAN limit=5,10:packet protocol=icmpv6;
    /ipv6 firewall raw add action=drop chain=icmp6 comment="drop other icmp" protocol=icmpv6;

    :put " - pcc load balancing on wan ports - protect mgmt ports";
    /ip firewall mangle add action=passthrough chain=prerouting connection-mark=no-mark connection-state=new in-interface-list=MGMT comment="MGMT->IN";
    
    :put " - pcc load balancing on wan ports - input/output chain";
    /ip firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface=wan1 new-connection-mark=ISP1_conn comment="WAN->IN";
    /ip firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface=wan2 new-connection-mark=ISP2_conn comment="WAN->IN";
    /ip firewall mangle add action=mark-routing chain=output connection-mark=ISP1_conn new-routing-mark=wan1_table_ipv4 comment="OUT->WAN";
    /ip firewall mangle add action=mark-routing chain=output connection-mark=ISP2_conn new-routing-mark=wan2_table_ipv4 comment="OUT->WAN";
    
    :put " - pcc load balancing on wan ports - forward chain";
    /ip firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface-list=LAN dst-address-list=!not_global_ipv4 per-connection-classifier=src-address-and-port:2/0 new-connection-mark=ISP1_conn comment="LAN->WAN";
    /ip firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface-list=LAN dst-address-list=!not_global_ipv4 per-connection-classifier=src-address-and-port:2/1 new-connection-mark=ISP2_conn comment="LAN->WAN";
    /ip firewall mangle add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=ISP1_conn new-routing-mark=wan1_table_ipv4 comment="LAN->WAN";
    /ip firewall mangle add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=ISP2_conn new-routing-mark=wan2_table_ipv4 comment="LAN->WAN";

    :put " - pcc load balancing on wan6 ports - protect mgmt ports";
    /ipv6 firewall mangle add action=passthrough chain=prerouting connection-mark=no-mark connection-state=new in-interface-list=MGMT comment="MGMT->IN";
    
    :put " - pcc load balancing on wan6 ports - input/output chain";
    /ipv6 firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface=wan1 new-connection-mark=ISP1_conn comment="WAN->IN";
    /ipv6 firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface=wan2 new-connection-mark=ISP2_conn comment="WAN->IN";
    /ipv6 firewall mangle add action=mark-routing chain=output connection-mark=ISP1_conn new-routing-mark=wan1_table_ipv6 comment="OUT->WAN";
    /ipv6 firewall mangle add action=mark-routing chain=output connection-mark=ISP2_conn new-routing-mark=wan2_table_ipv6 comment="OUT->WAN";
    
    :put " - pcc load balancing on wan6 ports - forward chain";
    /ipv6 firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface-list=LAN dst-address-list=!not_global_ipv6 per-connection-classifier=src-address-and-port:2/0 new-connection-mark=ISP1_conn comment="LAN->WAN";
    /ipv6 firewall mangle add action=mark-connection chain=prerouting connection-mark=no-mark connection-state=new in-interface-list=LAN dst-address-list=!not_global_ipv6 per-connection-classifier=src-address-and-port:2/1 new-connection-mark=ISP2_conn comment="LAN->WAN";
    /ipv6 firewall mangle add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=ISP1_conn new-routing-mark=wan1_table_ipv6 comment="LAN->WAN";
    /ipv6 firewall mangle add action=mark-routing chain=prerouting in-interface-list=LAN connection-mark=ISP2_conn new-routing-mark=wan2_table_ipv6 comment="LAN->WAN";
} on-error={ :put "!! error adding basic firewall rules"; };
