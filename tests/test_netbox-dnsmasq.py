"""Test suite for netbox-dnsmasq."""
import os

import pytest

from netbox_dnsmasq import (
    check_duplicates,
    format_dhcp,
    format_dns,
    get_ip_data,
    import_config,
    write_config,
)

# def test_restart_service():
#     assert False


def test_format_dns(caplog, example_netbox_data):
    """
    Test format_dns function for correct output based on input described in the example_netbox_data fixture.

    Args:
        caplog: Pytest fixture for capturing log output
        example_netbox_data: Pytest fixture for example Netbox data
    """
    dns_list = format_dns(example_netbox_data["dedup_dns"])
    assert dns_list == example_netbox_data["formatted_dns"]


def test_format_dns_merged(caplog, example_netbox_data):
    """
    Test format_dns function for correct merged IP output based on input described in the example_netbox_data fixture.

    Args:
        caplog: Pytest fixture for capturing log output
        example_netbox_data: Pytest fixture for example Netbox data
    """
    dns_list = format_dns(example_netbox_data["dedup_merged_dns"])
    assert dns_list == example_netbox_data["formatted_merged_dns"]


def test_format_dhcp(caplog, example_netbox_data):
    """
    Test format_dhcp function for correct output based on input described in the example_netbox_data fixture.

    Args:
        caplog: Pytest fixture for capturing log output
        example_netbox_data: Pytest fixture for example Netbox data
    """
    dhcp_list = format_dhcp(example_netbox_data["dedup_dhcp"])
    assert dhcp_list == example_netbox_data["formatted_dhcp"]


def test_write_config(caplog, example_netbox_data, tmp_path):
    """
    Test write_config function for correctly writing the dhcp and dns config files.

    Also test that the function raises a PermissionError when it is not able to write the config files.
    Args:
        caplog: Pytest fixture for capturing log output
        example_netbox_data: Pytest fixture for example Netbox data
    """
    dhcp_loc = tmp_path / "dhcp.conf"
    dns_loc = tmp_path / "dns.conf"
    write_config(
        dhcplist=example_netbox_data["formatted_dhcp"],
        dnslist=example_netbox_data["formatted_dns"],
        dhcp_loc=dhcp_loc,
        dns_loc=dns_loc,
    )
    assert dhcp_loc.read_text() == "".join(example_netbox_data["formatted_dhcp"])
    assert dns_loc.read_text() == "".join(example_netbox_data["formatted_dns"])
    assert "ERROR" not in caplog.text


@pytest.mark.vcr
def test_get_ip_data(
    caplog, example_netbox_data, example_config_data, set_test_environment
):
    """
    Test get_ip_data function for correct output as described in the example_netbox_data fixture.

    Will use VCR to record and replay API calls to Netbox.
    Default vcrpy setting is record_mode='none', which means that it will only replay previously recorded API calls.
    Args:
        caplog: Pytest fixture for capturing log output
        example_netbox_data: Pytest fixture for example Netbox data
        example_config_data: Pytest fixture for example config data
        set_test_environment: Pytest fixture for setting netbox environment variables
    """
    import pynetbox

    netbox_endpoint = os.environ["NETBOX_ENDPOINT"]
    netbox_token = os.environ["NETBOX_TOKEN"]
    api = pynetbox.api(url=netbox_endpoint, token=netbox_token)
    dhcp, dns = get_ip_data(dhcp_ignore_tag="no-dhcp", dhcp_tag="dhcp", nb=api)

    assert dhcp == example_netbox_data["dhcp"]
    assert dns == example_netbox_data["dns"]
    assert "ERROR" not in caplog.text


def test_check_duplicates(caplog, example_netbox_data):
    """
    Test check_duplicates function, including removing duplicate IPs for dns.

    Correct output will be based on input described in the example_netbox_data fixture.
    Args:
        caplog: Pytest fixture for capturing log output
        example_netbox_data: Pytest fixture for example Netbox data
    """
    nb_dhcp, nb_dns = check_duplicates(
        nb_dhcp=example_netbox_data["dhcp"],
        nb_dns=example_netbox_data["dns"],
        enable_duplicates=False,
    )
    assert nb_dhcp == example_netbox_data["dedup_dhcp"]
    assert nb_dns == example_netbox_data["dedup_dns"]
    assert "ERROR" not in caplog.text


def test_check_duplicates_no_remove(caplog, example_netbox_data):
    """
    Test check_duplicates function, including merging duplicate IPs for dns.

    Correct output will be based on input described in the example_netbox_data fixture.
    Args:
        caplog: Pytest fixture for capturing log output
        example_netbox_data: Pytest fixture for example Netbox data
    """
    nb_dhcp, nb_dns = check_duplicates(
        nb_dhcp=example_netbox_data["dhcp"],
        nb_dns=example_netbox_data["dns"],
        enable_duplicates=True,
    )
    assert nb_dhcp == example_netbox_data["dedup_dhcp"]
    assert nb_dns == example_netbox_data["dedup_merged_dns"]
    assert "ERROR" not in caplog.text


def test_import_config(caplog, set_test_environment):
    """
    Test import_config function for correct output in both dev and non-dev mode.

    Args:
        caplog: Pytest fixture for capturing log output
        set_test_environment: Pytest fixture for setting netbox environment variables
    """
    (
        netbox_endpoint,
        netbox_token,
        dhcp_config_location,
        dns_hosts_location,
    ) = import_config(dev=True)
    assert netbox_endpoint == os.environ["NETBOX_ENDPOINT"]
    assert netbox_token == os.environ["NETBOX_TOKEN"]
    assert dhcp_config_location == "dhcphosts.conf"
    assert dns_hosts_location == "dnsmasq.hosts"
    assert "ERROR" not in caplog.text

    (
        netbox_endpoint,
        netbox_token,
        dhcp_config_location,
        dns_hosts_location,
    ) = import_config(dev=False)
    assert netbox_endpoint == os.environ["NETBOX_ENDPOINT"]
    assert netbox_token == os.environ["NETBOX_TOKEN"]
    assert dhcp_config_location == "/etc/dnsmasq.d/dhcphosts.conf"
    assert dns_hosts_location == "/etc/dnsmasq.hosts"
    assert "ERROR" not in caplog.text


def test_import_config_missing_env(caplog, del_test_environment):
    """
    Test import_config function for correctly raising KeyError when environment variables are missing.

    Args:
        caplog: Pytest fixture for capturing log output
        del_test_environment: Pytest fixture for deleting netbox environment variables
    """
    with pytest.raises(KeyError):
        import_config(dev=False)
    assert "Missing Environment variable: 'NETBOX_ENDPOINT'" in caplog.text
