#!/usr/bin/python3
import pynetbox
import re
from subprocess import CalledProcessError, run
import os
import sys
import argparse
from loguru import logger


def import_config(dev: bool = False) -> tuple[str, str, str, str]:
    """
    Import config from environment variables
    Args:
        dev (bool): If True, write config files to current directory and disable restart of dnsmasq
    Returns:
        endpoint (str): Netbox API endpoint
        token (str): Netbox API token
        dhcp_config (str): Path to DHCP config file
        dns_hosts (str): Path to DNS config file
    """
    try:
        endpoint = os.environ['NETBOX_ENDPOINT']
        token = os.environ['NETBOX_TOKEN']
    except KeyError as e:
        print(f'Missing Environment variable: {e}')
        exit(1)
    if dev:
        dhcp_config = "dhcphosts.conf"
        dns_hosts = "dnsmasq.hosts"
    else:
        dhcp_config = "/etc/dnsmasq.d/dhcphosts.conf"
        dns_hosts = "/etc/dnsmasq.hosts"
    logger.debug(f'Netbox endpoint is {endpoint}')
    logger.debug(f'Config file locations are {dhcp_config} and {dns_hosts}')
    return endpoint, token, dhcp_config, dns_hosts


def get_ip_data(dhcp_ignore_tag: str, dhcp_tag: str) -> tuple[dict, dict]:
    """
    Get IP&DNS data from Netbox and return a dictionary of DHCP and DNS data.
    Args:
        dhcp_ignore_tag (str): Netbox tag to ignore IP addresses
        dhcp_tag (str): Netbox tag to include IP addresses
    Returns:
        dhcp_data (dict): Dictionary of DHCP data
        dns_data (dict): Dictionary of DNS data
    """
    nb_dhcp = {}
    nb_dns = {}
    dhcp_prefixes = nb.ipam.prefixes.filter(tag=[dhcp_tag])
    ip_addresses = nb.ipam.ip_addresses.filter(tag=[dhcp_ignore_tag])
    for ip in ip_addresses:
        ip_address = re.sub('/.*', '', ip.address)
        if len(ip.dns_name) > 0:
            nb_dns.update({ip_address: {'tags': [], 'hostname': ''}})
        else:
            logger.warning(f"Warning: {ip_address} has {dhcp_ignore_tag} tag, but no FQDN.")
            continue
        for tag in ip.tags:
            if ip.dns_name:
                nb_dns[ip_address]['tags'].append(tag)
        if dhcp_tag in list(t.name for t in ip.tags):
            logger.warning(f"Warning: {ip} has {dhcp_tag} tag, but also has {dhcp_ignore_tag} tag.")
        if len(ip.dns_name) > 0:
            if ip.dns_name:
                nb_dns[ip_address]['hostname'] = ip.dns_name
                logger.debug(f'Added DNS Host {ip.dns_name} with IP {ip_address}')
    for prefix in dhcp_prefixes:
        prefix_ips = nb.ipam.ip_addresses.filter(parent=prefix.prefix)
        for ip in prefix_ips:
            ip_address = re.sub('/.*', '', ip.address)
            if ip.assigned_object_id:
                if ip.assigned_object.mac_address is not None and dhcp_ignore_tag not in list(t.name for t in ip.tags):
                    mac = ip.assigned_object.mac_address.lower()
                    nb_dhcp.update({ip_address: {'mac': '', 'tags': [], 'hostname': ''}})
                    nb_dhcp[ip_address]['mac'] = mac
                    logger.debug(f'Added DHCP host with MAC {mac} and IP {ip_address}')
                else:
                    continue
                for tag in ip.tags:
                    if mac:
                        nb_dhcp[ip_address]['tags'].append(tag)
                if len(ip.dns_name) > 0:
                    if mac:
                        nb_dhcp[ip_address]['hostname'] = ip.dns_name
            else:
                continue
    return nb_dhcp, nb_dns


def format_dhcp(data: dict) -> list:
    """
    Format DHCP data for dnsmasq
    Args:
        data (dict): Dictionary of DHCP data from Netbox
    Returns:
        dhcp_list (list): List of DHCP config lines
    """
    dhcp_list = []
    for ip in data:
        host = ["dhcp-host=", data[ip]['mac']]
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
        dhcp_list.append(host)
    return dhcp_list


def format_dns(data: dict) -> list:
    """
    Format DNS data for dnsmasq
    Args:
        data (dict): Dictionary of DNS data from Netbox
    Returns:
        dnslist (list): List of DNS config lines
    """
    dns_list = []
    for ip in data:
        host = [ip]
        if len(data[ip]['hostname']) > 0:
            host.append(f" {data[ip]['hostname']}")
        else:
            continue
        host.append("\n")
        host = ''.join(host)
        dns_list.append(host)
    return dns_list


def write_config(dhcplist: list, dnslist: list) -> None:
    """
    Write DHCP and DNS config files.
    Args:
        dhcplist (list): List of DHCP config lines
        dnslist (list): List of DNS config lines
    Returns:
        None
    """
    try:
        dhcpconfig = open(DHCP_config_location, "w")
        dhcpconfig.writelines(dhcplist)
        dhcpconfig.close()
        dnsconfig = open(DNS_hosts_location, "w")
        dnsconfig.writelines(dnslist)
        dnsconfig.close()
    except PermissionError as e:
        logger.error(f'Received error "{e.strerror}" while writing config {e.filename}')
        exit(1)


def restart_service() -> None:
    """
    Restart Dnsmasq service
    Returns:
        None
    """
    try:
        run(["systemctl", "restart", "dnsmasq"], check=True, capture_output=True)
        logger.info("Restarted Dnsmasq.")
    except CalledProcessError as e:
        logger.error(f'Error: {e.stderr.decode()}')
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', help="more verbose feedback")
    parser.add_argument('--dev', action='store_true',
                        help="save configs to current directory and disable dnsmasq restart")
    parser.add_argument('-t', '--tag', default='dhcp',
                        help="netbox tag that will be used to search for prefixes"
                             " to include in DHCP config  (default: dhcp)")
    parser.add_argument('--dns-tag', default='no-dhcp',
                        help="netbox tag that will be used to mark IP's"
                             " to only be included in DNS config (default: no-dhcp)")
    args = parser.parse_args()

    logger.remove(0)
    logger.add(sys.stderr, level="DEBUG" if args.debug else "INFO")
    NETBOX_ENDPOINT, NETBOX_TOKEN, DHCP_config_location, DNS_hosts_location = import_config(args.dev)

    nb = pynetbox.api(url=NETBOX_ENDPOINT, token=NETBOX_TOKEN)

    dhcp, dns = get_ip_data(args.dns_tag, args.tag)
    dhcp_data = format_dhcp(dhcp)
    dns_data = format_dns(dns)
    write_config(dhcp_data, dns_data)
    if not args.dev:
        restart_service()
