# Netbox-dnsmasq
Create dnsmasq DHCP/DNS configs using the Netbox API.

Set your Netbox Instance as a environment variable `NETBOX_ENDPOINT` and your API token as `NETBOX_TOKEN`

Configs will be saved in the following two locations:  
DHCP config location: `/etc/dnsmasq.d/dhcphosts.conf`  
DNS hosts file location: `/etc/dnsmasq.hosts`

Prefixes that should be scanned for Hosts need to be tagged with the tag "dhcp" in Netbox.  
IPs that should not be installed in the DHCP config or installed as DNS records need to be tagged with "no-dhcp" in Netbox.  
The DNS adding will also work for singular IPs outside Prefixes.

This python program will also use other tags applied to the IP address and use them as the Set for dnsmasq.  
This is important if you have multiple Vlans for example and want dnsmasq to manage the different options based on the sets.

Output will for example be the following:

```
dhcp-host=74-18-63-53-73-60,10.1.11.140,phone,set:wifi
dhcp-host=04-12-B2-99-25-E8,10.2.22.110,vm-machine1,set:vmnet
dhcp-host=04-55-04-DF-A1-5E,10.2.22.129,vm-machine2,set:vmnet
dhcp-host=52-3E-EC-4C-9A-F8,10.2.22.200,vm-machine3,set:vmnet
dhcp-host=12-80-1E-32-B8-C7,10.2.22.202,vm-machine4,set:vmnet
dhcp-host=45-B5-C3-9F-CE-EC,10.3.33.10,public-dns,set:public
```

An example config for dnsmasq would look like the following:

```
dnssec
dnssec-check-unsigned
no-resolv
local=/local.domain/
local=/second-local.domain/
no-hosts
expand-hosts
dhcp-authoritative
log-queries
#log-dhcp
#dhcp-ignore=tag:!known
addn-hosts=/etc/dnsmasq.hosts

domain=dhcp.local.domain

dhcp-range=set:wifi,10.1.11.100,10.1.11.220,255.255.255.0,24h
domain=wifi.local.domain,10.1.11.0/24
dhcp-option = tag:wifi, option:router, 10.1.11.1

dhcp-range=set:vmnet,10.2.22.100,10.2.22.220,255.255.255.0,24h
domain=vm.local.domain,10.2.22.0/24
dhcp-option = tag:vmnet, option:router, 10.2.22.1

dhcp-range=set:public,10.3.33.100,10.3.33.220,255.255.255.0,24h
domain=p.local.domain,10.3.33.0/24
dhcp-option = tag:public, option:router, 10.3.33.1

dhcp-option = option:ntp-server, 10.0.0.1
dhcp-option = option:dns-server, 10.0.0.2
```

## Roadmap:
- Test config for duplicate MACs (outside IPv4/IPv6)
- Support multiple domains for a single IP
- Suggestions welcome
