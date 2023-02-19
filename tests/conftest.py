import pytest
from loguru import logger
from _pytest.logging import LogCaptureFixture


@pytest.fixture(autouse=True)
def caplog(caplog: LogCaptureFixture):
    """
    Extend the caplog fixture to also capture loguru logs.
    See:
    https://loguru.readthedocs.io/en/stable/resources/migration.html#making-things-work-with-pytest-and-caplog
    """
    handler_id = logger.add(caplog.handler, format="{message}")
    yield caplog
    logger.remove(handler_id)


@pytest.fixture
def example_config_data():
    """
    This is a helper function to return a dictionary of example config data.
    Returns:
        dict: A dictionary of example config data.
    """
    return {
        "args": {
            "debug":                True,
            "dev":                  True,
            "tag":                  'dhcp',
            "dns_tag":              'no-dhcp',
            "remove_duplicate_ips": True
        }
    }


@pytest.fixture
def example_netbox_data():
    """
    This is a helper function to return a dictionary of example data from Netbox.
    Returns:
        dict: A dictionary of example data from Netbox.
    """
    return {
        'dns': {
            'test123.example.com':     {'tags': ['no-dhcp'], 'ip': '1.1.1.1'},
            'testdns2.example.com':    {'tags': ['no-dhcp'], 'ip': '1.1.1.2'},
            'nonworking2.example.com': {'tags': ['dhcp', 'no-dhcp'], 'ip': '10.1.1.1'},
            'duplicateip.example.com': {'tags': ['no-dhcp'], 'ip': '10.1.1.1'},
            'nonworking.example.com':  {'tags': ['no-dhcp'], 'ip': '10.80.20.30'},
        },
        'dhcp': {
            '1.1.1.1':   {'mac': '74:18:63:53:73:60', 'tags': [], 'hostname': 'testdns.example.com'},
            '1.1.1.111': {'mac': '74:18:63:53:aa:aa', 'tags': [], 'hostname': 'workingdhcp.example.com'},
            '1.1.1.222': {'mac': '74:18:63:53:73:60', 'tags': [], 'hostname': ''},
            '9.9.9.9':   {'mac':  '74:18:63:53:73:99', 'tags': [], 'hostname': ''},
            '2a00::1':   {'mac': '74:18:63:53:73:99', 'tags': [], 'hostname': ''}
        },
        'dedup_dns': {
            'test123.example.com': {'tags': ['no-dhcp'], 'ip': '1.1.1.1'},
            'testdns2.example.com': {'tags': ['no-dhcp'], 'ip': '1.1.1.2'},
            'duplicateip.example.com': {'ip': '10.1.1.1', 'tags': ['no-dhcp']},
            'nonworking.example.com': {'tags': ['no-dhcp'], 'ip': '10.80.20.30'}
        },
        'dedup_merged_dns': {
            'test123.example.com':     {'tags': ['no-dhcp'], 'ip': '1.1.1.1'},
            'testdns2.example.com':    {'tags': ['no-dhcp'], 'ip': '1.1.1.2'},
            'nonworking2.example.com': {
                'tags': ['dhcp', 'no-dhcp'],
                'ip': '10.1.1.1',
                'secondary': ['duplicateip.example.com']
            },
            'nonworking.example.com':  {'tags': ['no-dhcp'], 'ip': '10.80.20.30'}
        },
        'dedup_dhcp': {
            '1.1.1.111': {'mac': '74:18:63:53:aa:aa', 'tags': [], 'hostname': 'workingdhcp.example.com'},
            '1.1.1.222': {'mac': '74:18:63:53:73:60', 'tags': [], 'hostname': ''},
            '2a00::1':   {'mac': '74:18:63:53:73:99', 'tags': [], 'hostname': ''}
        },
        'formatted_dns': [
            '1.1.1.1 test123.example.com\n',
            '1.1.1.2 testdns2.example.com\n',
            '10.1.1.1 duplicateip.example.com\n',
            '10.80.20.30 nonworking.example.com\n'
        ],
        'formatted_merged_dns': [
            '1.1.1.1 test123.example.com\n',
            '1.1.1.2 testdns2.example.com\n',
            '10.1.1.1 nonworking2.example.com duplicateip.example.com\n',
            '10.80.20.30 nonworking.example.com\n'
        ],
        'formatted_dhcp': [
            'dhcp-host=74:18:63:53:aa:aa,1.1.1.111,workingdhcp.example.com\n',
            'dhcp-host=74:18:63:53:73:60,1.1.1.222\n',
            'dhcp-host=74:18:63:53:73:99,[2a00::1]\n'
        ]
    }


@pytest.fixture
def set_test_environment(monkeypatch):
    """
    This is a helper function to set Netbox environment variables.
    """
    monkeypatch.setenv("NETBOX_ENDPOINT", "http://10.1.0.171:8000")
    monkeypatch.setenv("NETBOX_TOKEN", "0123456789abcdef0123456789abcdef01234567")


@pytest.fixture
def del_test_environment(monkeypatch):
    """
    This is a helper function to delete Netbox environment variables.
    """
    monkeypatch.delenv("NETBOX_ENDPOINT", raising=False)
    monkeypatch.delenv("NETBOX_TOKEN", raising=False)
