#!/usr/bin/env python3
# noqa: E265

"""Main script for netbox_dnsmasq."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from subprocess import CalledProcessError, run
from typing import List, TypedDict

import pynetbox
from loguru import logger


def import_config(dev: bool = False) -> tuple[str, str, str, str]:
    """
    Import config from environment variables.

    Args:
        dev (bool): If True, write config files to current directory and disable restart of dnsmasq
    Returns:
        endpoint (str): Netbox API endpoint
        token (str): Netbox API token
        dhcp_config (str): Path to DHCP config file
        dns_hosts (str): Path to DNS config file
    """
    try:
        endpoint = os.environ["NETBOX_ENDPOINT"]
        token = os.environ["NETBOX_TOKEN"]
    except KeyError as e:
        logger.error(f"Missing Environment variable: {e}")
        raise
    if dev:
        dhcp_config = "dhcphosts.conf"
        dns_hosts = "dnsmasq.hosts"
    else:
        dhcp_config = "/etc/dnsmasq.d/dhcphosts.conf"
        dns_hosts = "/etc/dnsmasq.hosts"
    logger.debug(f"Netbox endpoint is {endpoint}")
    logger.debug(f"Config file locations are {dhcp_config} and {dns_hosts}")
    return endpoint, token, dhcp_config, dns_hosts


def check_duplicates(
    nb_dhcp: dict, nb_dns: dict, enable_duplicates: bool
) -> tuple[dict, dict]:
    """
    Check for duplicate MAC addresses in the data Netbox returned, warn, and remove from DHCP data.

    If enabled via CLI parameter, enable duplicate IP addresses in DNS data.
    Otherwise, duplicate IP's will be removed.
    Args:
        nb_dhcp (dict): Dictionary of DHCP data
        nb_dns (dict): Dictionary of DNS data
        enable_duplicates (bool): If True, duplicate IP addresses will be merged to one entry
    Returns:
        nb_dhcp (dict): Dictionary of DHCP data
        nb_dns (dict): Dictionary of DNS data
    """
    dhcp_ips = []
    dhcp_macs = []
    for ip in nb_dhcp:
        dhcp_ips.append(ip)
        dhcp_macs.append(nb_dhcp[ip]["mac"])
    if len(dhcp_macs) != len(set(dhcp_macs)) or len(dhcp_ips) != len(set(dhcp_ips)):
        logger.warning(
            "Duplicate MAC or IP addresses found. Removing from DHCP config."
        )
        for k, v in nb_dhcp.copy().items():
            if dhcp_macs.count(v["mac"]) > 1 or dhcp_ips.count(k) > 1:
                logger.info(
                    f"Duplicate MAC found: {v['mac']} - {k} - removing from DHCP config."
                )
                del dhcp_macs[dhcp_macs.index(v["mac"])]
                del dhcp_ips[dhcp_ips.index(k)]
                del nb_dhcp[k]
            if len(dhcp_macs) == len(set(dhcp_macs)) and len(dhcp_ips) == len(
                set(dhcp_ips)
            ):
                break
    dns_ips = []
    for fqdn in nb_dns:
        dns_ips.append(nb_dns[fqdn]["ip"])
    if len(dns_ips) != len(set(dns_ips)):
        logger.warning("Duplicate IP addresses in DNS config found.")
        for k, v in nb_dns.copy().items():
            if dns_ips.count(v["ip"]) > 1:
                if not enable_duplicates:
                    logger.info(
                        f"Duplicate IP address {v['ip']} found. Removing from DNS config."
                    )
                    del dns_ips[dns_ips.index(v["ip"])]
                    del nb_dns[k]
                else:
                    if k in nb_dns:
                        logger.info(
                            f"Duplicate IP address {v['ip']} found. "
                            "Related FQDN's will be merged into one entry."
                        )
                        for k2, v2 in nb_dns.copy().items():
                            if v2["ip"] == v["ip"] and k2 != k:
                                logger.info(f"Merging {k2} with {k}")
                                if "secondary" not in nb_dns[k]:
                                    nb_dns[k]["secondary"] = [k2]
                                else:
                                    nb_dns[k]["secondary"].append(k2)
                                del nb_dns[k2]
            if len(dns_ips) == len(set(dns_ips)):
                break
    return nb_dhcp, nb_dns


def get_ip_data(
    dhcp_ignore_tag: str, dhcp_tag: str, nb: pynetbox.api
) -> tuple[dict, dict]:
    """
    Get IP&DNS data from Netbox and return a dictionary of DHCP and DNS data.

    Args:
        dhcp_ignore_tag (str): Netbox tag to ignore IP addresses
        dhcp_tag (str): Netbox tag to include IP addresses
        nb (pynetbox.api): Netbox API object
    Returns:
        dhcp_data (dict): Dictionary of DHCP data
        dns_data (dict): Dictionary of DNS data
    """

    class DhcpType(TypedDict):
        """TypedDict for DHCP data."""

        hostname: str
        mac: str
        tags: List[str]

    class DnsType(TypedDict):
        """TypedDict for DNS data."""

        ip: str
        tags: List[str]

    nb_dhcp = {}
    nb_dns = {}
    dhcp_prefixes = nb.ipam.prefixes.filter(tag=[dhcp_tag])
    ip_addresses = nb.ipam.ip_addresses.filter(tag=[dhcp_ignore_tag])

    # create cache for dcim.interfaces as looking up mac addresses within loop is quite slow
    interface_cache = {}
    for iface in nb.dcim.interfaces.all():
        interface_cache[iface.id] = iface

    for ip in ip_addresses:
        ip_address = re.sub("/.*", "", ip.address)
        if len(ip.dns_name) > 0:
            nb_dns.update({ip.dns_name: DnsType({"ip": "", "tags": []})})
        else:
            logger.warning(f"{ip_address} has {dhcp_ignore_tag} tag, but no FQDN.")
            continue
        for tag in ip.tags:
            if ip.dns_name:
                nb_dns[ip.dns_name]["tags"].append(tag.name)
        if dhcp_tag in list(t.name for t in ip.tags):
            logger.warning(
                f"{ip} has {dhcp_tag} tag, but also has {dhcp_ignore_tag} tag."
            )
        if len(ip.dns_name) > 0:
            if ip.dns_name:
                nb_dns[ip.dns_name]["ip"] = ip_address
                logger.debug(f"Added DNS Host {ip.dns_name} with IP {ip_address}")
    for prefix in dhcp_prefixes:
        prefix_ips = nb.ipam.ip_addresses.filter(parent=prefix.prefix)
        for ip in prefix_ips:
            ip_address = re.sub("/.*", "", ip.address)
            if ip.assigned_object_id:
                mac_address = interface_cache[ip.assigned_object_id].mac_address \
                    if ip.assigned_object_id in interface_cache else ip.assigned_object.mac_address
                if (
                    mac_address is not None
                    and dhcp_ignore_tag not in list(t.name for t in ip.tags)
                ):
                    mac = mac_address.lower()
                    if ip_address in nb_dhcp:
                        logger.warning(
                            f"Duplicate IP address {ip_address}"
                            f" with MAC {mac} found in DHCP config. Skipping."
                        )
                        continue
                    nb_dhcp.update(
                        {ip_address: DhcpType({"mac": "", "tags": [], "hostname": ""})}
                    )
                    nb_dhcp[ip_address]["mac"] = mac
                    logger.debug(f"Added DHCP host with MAC {mac} and IP {ip_address}")
                else:
                    continue
                for tag in ip.tags:
                    if mac:
                        nb_dhcp[ip_address]["tags"].append(tag.name)
                if len(ip.dns_name) > 0:
                    if mac:
                        nb_dhcp[ip_address]["hostname"] = ip.dns_name
            else:
                continue
    return nb_dhcp, nb_dns


def format_dhcp(data: dict) -> list:
    """
    Format DHCP data for dnsmasq.

    Args:
        data (dict): Dictionary of DHCP data from Netbox
    Returns:
        dhcp_list (list): List of DHCP config lines
    """
    dhcp_list = []
    for ip in data:
        host = ["dhcp-host=", data[ip]["mac"]]
        if ":" in ip:
            host.append(f",[{ip}]")
        else:
            host.append(f",{ip}")
        if len(data[ip]["hostname"]) > 0:
            host.append(f",{data[ip]['hostname']}")
        for tag in data[ip]["tags"]:
            if "set:" in host[-1]:
                logger.warning(
                    f"More than one tag for DHCP IP {ip} found. " f"Skipping tag {tag}."
                )
                continue
            host.append(f",set:{tag}")
        host.append("\n")
        line_host = "".join(host)
        dhcp_list.append(line_host)
    return dhcp_list


def format_dns(data: dict) -> list:
    """
    Format DNS data for dnsmasq.

    If a host has secondary FQDN's, they will be appended to the primary FQDN.
    Args:
        data (dict): Dictionary of DNS data from Netbox
    Returns:
        dnslist (list): List of DNS config lines
    """
    dns_list = []
    for hostname in data:
        if "secondary" in data[hostname]:
            secondaries = " ".join(data[hostname]["secondary"])
            merged_name = f"{hostname} {secondaries}"
            host = f'{data[hostname]["ip"]} {str(merged_name)}\n'
        else:
            host = f'{data[hostname]["ip"]} {str(hostname)}\n'

        dns_list.append(host)
    return dns_list


def write_config(
    dhcplist: list,
    dnslist: list,
    dns_loc: str | pathlib.Path,
    dhcp_loc: str | pathlib.Path,
) -> None:
    """
    Write DHCP and DNS config files.

    Args:
        dhcplist (list): List of DHCP config lines
        dnslist (list): List of DNS config lines
        dns_loc (str): Location to write DNS config file to
        dhcp_loc (str): Location to write DHCP config file to
    Returns:
        None
    """
    try:
        dhcpconfig = open(dhcp_loc, "w")
        dhcpconfig.writelines(dhcplist)
        dhcpconfig.close()
        dnsconfig = open(dns_loc, "w")
        dnsconfig.writelines(dnslist)
        dnsconfig.close()
    except PermissionError as e:
        logger.error(f'Received error "{e.strerror}" while writing config {e.filename}')
        raise


def restart_service() -> None:
    """
    Restart Dnsmasq service.

    Returns:
        None
    """
    try:
        run(["systemctl", "restart", "dnsmasq"], check=True, capture_output=True)
        logger.info("Restarted Dnsmasq.")
    except CalledProcessError as e:
        logger.error(f"Error: {e.stderr.decode()}")
        exit(1)


def main() -> None:
    """
    Run argparse and start the script.

    Returns:
        None
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-d", "--debug", action="store_true", help="more verbose feedback"
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="save configs to current directory and disable dnsmasq restart",
    )
    parser.add_argument(
        "-t",
        "--tag",
        default="dhcp",
        help="netbox tag that will be used to search for prefixes"
        " to include in DHCP config  (default: dhcp)",
    )
    parser.add_argument(
        "--dns-tag",
        default="no-dhcp",
        help="netbox tag that will be used to mark IP's"
        " to only be included in DNS config (default: no-dhcp)",
    )
    parser.add_argument(
        "-e",
        "--enable-duplicate-ips",
        action="store_true",
        help="enable & merge duplicate IP's in DNS config",
    )
    args = parser.parse_args()

    logger.remove(0)
    logger.add(sys.stderr, level="DEBUG" if args.debug else "INFO")
    (
        NETBOX_ENDPOINT,
        NETBOX_TOKEN,
        DHCP_config_location,
        DNS_hosts_location,
    ) = import_config(args.dev)

    api = pynetbox.api(url=NETBOX_ENDPOINT, token=NETBOX_TOKEN, threading=True)

    dhcp, dns = get_ip_data(args.dns_tag, args.tag, nb=api)
    check_duplicates(
        nb_dhcp=dhcp, nb_dns=dns, enable_duplicates=args.enable_duplicate_ips
    )
    dhcp_data = format_dhcp(dhcp)
    dns_data = format_dns(dns)
    write_config(
        dhcplist=dhcp_data,
        dnslist=dns_data,
        dns_loc=DNS_hosts_location,
        dhcp_loc=DHCP_config_location,
    )
    if not args.dev:
        restart_service()


if __name__ == "__main__":
    main()
