# infurnex/tests/test_agent.py
import pytest # standard testing framework

# Adding path to make absolute imports work cleanly in script
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sandbox import enforce_network_policy # import policy checker
from tools import check_host_allowlist # import tool checker

def test_sandbox_blocks_external_ips():
    # Test that external targets are completely rejected
    assert enforce_network_policy("http://google.com") == False # verify block
    assert enforce_network_policy("http://8.8.8.8") == False # verify block

def test_sandbox_allows_internal_targets():
    # Test that allowed targets pass the check
    assert enforce_network_policy("http://target.local:8080") == True # verify allow
    assert enforce_network_policy("http://127.0.0.1") == True # verify allow

def test_tool_registry_host_check():
    # Ensure tool registry checks mimic sandbox validation
    assert check_host_allowlist("http://target.local") == True # verify allow
    assert check_host_allowlist("http://evil.com") == False # verify block
