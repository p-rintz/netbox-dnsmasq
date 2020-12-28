#!/usr/bin/python3
import pynetbox
import re
from subprocess import CalledProcessError, run
import signal
import os
import argparse


def import_config():
    try:
        NETBOX_ENDPOINT = os.environ['NETBOX_ENDPOINT']
        NETBOX_TOKEN = os.environ['NETBOX_TOKEN']
    except KeyError as e:
        print(f'Missing Environment variable: {e}')
        exit(1)
    DHCP_config_location = "/etc/dnsmasq.d/dhcphosts.conf"
    DNS_hosts_location = "/etc/dnsmasq.hosts"
    return NETBOX_ENDPOINT, NETBOX_TOKEN, DHCP_config_location, DNS_hosts_location


def get_ip_data():
    dhcp_data = {}
    dns_data = {}
    dhcp_prefixes = nb.ipam.prefixes.filter(tag=["dhcp"])
    ip_addresses = nb.ipam.ip_addresses.filter(tag=["no-dhcp"])
    for ip in ip_addresses:
        ip_address = re.sub('/.*', '', ip.address)
        if len(ip.dns_name) > 0:
            dns_data.update({ip_address: {'tags': [], 'hostname': ''}})
        else:
            print(f"Warning: {ip_address} has 'no-dhcp' tag, but no FQDN.")
            continue
        for tag in ip.tags:
            if ip.dns_name:
                dns_data[ip_address]['tags'].append(tag)
        if len(ip.dns_name) > 0:
            if ip.dns_name:
                dns_data[ip_address]['hostname'] = ip.dns_name
                if args.debug:
                    print(f'Added DNS Host {ip.dns_name} with IP {ip_address}')
    for prefix in dhcp_prefixes:
        prefix_ips = nb.ipam.ip_addresses.filter(parent=prefix.prefix)
        for ip in prefix_ips:
            mac = None
            ip_address = re.sub('/.*', '', ip.address)
            if ip.assigned_object_id:
                if ip.assigned_object.mac_address is not None and 'no-dhcp' not in list(t.name for t in ip.tags):
                    mac = ip.assigned_object.mac_address.lower()
                    dhcp_data.update({ip_address: {'mac': '', 'tags': [], 'hostname': ''}})
                    dhcp_data[ip_address]['mac'] = mac
                    if args.debug:
                        print(f'Added DHCP host with MAC {mac} and IP {ip_address}')
                else:
                    continue
                for tag in ip.tags:
                    if mac:
                        dhcp_data[ip_address]['tags'].append(tag)
                if len(ip.dns_name) > 0:
                    if mac:
                        dhcp_data[ip_address]['hostname'] = ip.dns_name
            else:
                continue
    return dhcp_data, dns_data


def format_dhcp(data):
    dhcplist = []
    for ip in data:
        host = []
        host.append("dhcp-host=")
        host.append(data[ip]['mac'])
        if ":" in ip:
            host.append(f",[{ip}]")
        else:
            host.append(f",{ip}")
        if len(data[ip]['hostname']) > 0:
            host.append(f",{data[ip]['hostname']}")
        for tag in data[ip]['tags']:
            host.append(f",set:{tag.slug}")
        host.append("\n")
        host = ''.join(host)
        dhcplist.append(host)
    return dhcplist


def format_dns(data):
    dnslist = []
    for ip in data:
        host = []
        host.append(ip)
        if len(data[ip]['hostname']) > 0:
            host.append(f" {data[ip]['hostname']}")
        else:
            continue
        host.append("\n")
        host = ''.join(host)
        dnslist.append(host)
    return dnslist


def write_config(dhcplist, dnslist):
    try:
        dhcpconfig = open(DHCP_config_location, "w")
        dhcpconfig.writelines(dhcplist)
        dhcpconfig.close
        dnsconfig = open(DNS_hosts_location, "w")
        dnsconfig.writelines(dnslist)
        dnsconfig.close
    except PermissionError as e:
        print(f'Received error "{e.strerror}" while writing config {e.filename}')
        exit(1)


def restart_service():
    try:
        run(["systemctl", "restart", "dnsmasq"], check=True, capture_output=True)
        print("Restarted Dnsmasq.")
    except CalledProcessError as e:
        print(f'Error: {e.stderr.decode()}')
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help="more verbose feedback")
    args = parser.parse_args()

    NETBOX_ENDPOINT, NETBOX_TOKEN, DHCP_config_location, DNS_hosts_location = import_config()

    nb = pynetbox.api(url=NETBOX_ENDPOINT, token=NETBOX_TOKEN)

    dhcp_data, dns_data = get_ip_data()
    dhcplist = format_dhcp(dhcp_data)
    dnslist = format_dns(dns_data)
    write_config(dhcplist, dnslist)
    restart_service()
