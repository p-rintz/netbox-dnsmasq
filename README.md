# Netbox-dnsmasq
Create dnsmasq DHCP/DNS configs using the Netbox API.

<!-- Pytest Coverage Comment:Begin -->
\n<!-- Pytest Coverage Comment:End -->

## Configuration

**Set your Netbox Instance as a environment variable `NETBOX_ENDPOINT` and your API token as `NETBOX_TOKEN`**  
Install the required python packages:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
**Python 3.7 or higher is required.**

### Config locations

Configs will, by default, be saved in the following two locations:  
**DHCP config location**: `/etc/dnsmasq.d/dhcphosts.conf`  
**DNS hosts file location**: `/etc/dnsmasq.hosts`

### DHCP Config
**Prefixes** that should be scanned for Hosts, by default, need to be tagged with the tag "dhcp" in Netbox.  
IPs that should not be installed in the DHCP config or installed as DNS records need to be tagged with "no-dhcp" in Netbox.  
You can change the DHCP tag to something else by using the `--tag` CLI parameter.

If you like, you can change both tags to something else by using the `--tag` and `--dns-tag` CLI parameters. 

This python script will also use other tags applied to the IP address and use them as the Set for dnsmasq.  
This is important if you have multiple Vlans for example and want dnsmasq to manage the different options based on the sets.

**Please be aware that only one tag can be used for set in dnsmasq.**  
Every tag after the first will be ignored and warned about.  

### DNS Config
**IP's** that should be installed in the DNS config, by default, need to be tagged with the tag "no-dhcp" in Netbox.  
You can change this tag to something else by using the `--dns-tag` CLI parameter.

By default, single IP's cannot be added multiple times to the DNS config.   
This can be changed by using the `--enable-duplicate-ips` CLI parameter.  
Duplicate IP's will then be merged to a single line in the DNS config.

Example:  
`10.1.1.1 nonworking2.example.com duplicateip.example.com`

### Available CLI parameters are:

```
usage: netbox_dnsmasq.py [-h] [-d] [--dev] [-t TAG] [--dns-tag DNS_TAG] [-e]

options:
  -h, --help                  show this help message and exit
  -d, --debug                 more verbose feedback
  --dev                       save configs to current directory and disable dnsmasq restart
  -t TAG, --tag TAG           netbox tag that will be used to search for prefixes to include in DHCP config (default: dhcp)
  --dns-tag DNS_TAG           netbox tag that will be used to mark IP's to only be included in DNS config (default: no-dhcp)
  -e, --enable-duplicate-ips  enable & merge duplicate IP's in DNS config
```

## Examples

Example output could for example be the following:

```
dhcp-host=74-18-63-53-73-60,10.1.11.140,phone,set:wifi
dhcp-host=04-12-B2-99-25-E8,10.2.22.110,vm-machine1,set:vmnet
dhcp-host=04-55-04-DF-A1-5E,10.2.22.129,vm-machine2,set:vmnet
dhcp-host=52-3E-EC-4C-9A-F8,10.2.22.200,vm-machine3,set:vmnet
dhcp-host=12-80-1E-32-B8-C7,10.2.22.202,vm-machine4,set:vmnet
dhcp-host=45-B5-C3-9F-CE-EC,10.3.33.10,public-dns,set:public
```

An example config for dnsmasq with sets would look like the following:

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
- Enable setting of config file locations via CLI
- Suggestions welcome
