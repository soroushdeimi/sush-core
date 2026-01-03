import asyncio
import json
import logging
import os
import sys

# Add project root to path
sys.path.append(os.getcwd())

# --- MOCK MISSING DEPENDENCIES FOR TESTING LOGIC ONLY ---
from unittest.mock import MagicMock

sys.modules["kyber_py"] = MagicMock()
sys.modules["kyber_py.kyber768"] = MagicMock()


# Also mock the module that raises the error
class MockMLKEM:
    def generate_keypair(self):
        return b"pub", b"priv"

    def encapsulate(self, pk):
        return b"c", b"ss"

    def decapsulate(self, c, sk):
        return b"ss"

    def derive_keys(self, ss, sid):
        return {"encryption_key": b"k" * 32}


# We need to patch sys.modules before importing sush.core.ml_kem
# But sush.core.ml_kem raises ImportError at module level.
# We can try to patch it directly in sys.modules
import types

mock_ml_kem_mod = types.ModuleType("sush.core.ml_kem")
mock_ml_kem_mod.MLKEMKeyExchange = MockMLKEM
sys.modules["sush.core.ml_kem"] = mock_ml_kem_mod

from sush.server import ServerConfig, SushServer

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("TestDirectory")


async def test_directory_flow():
    print("--- Starting Directory Protocol Test ---")

    # 1. Setup Directory Server
    config = ServerConfig(
        node_id="dir_server_01", listen_ports=[9090], is_directory_server=True, log_level="DEBUG"
    )
    server = SushServer(config)

    # Mock internal components to avoid full network startup
    server.node_integrity.node_registry = {}

    # 2. Create Client connection (Simulated)
    class MockWriter:
        def __init__(self):
            self.data = b""
            self.closed = False

        def write(self, data):
            self.data += data

        async def drain(self):
            pass

        def close(self):
            self.closed = True

        async def wait_closed(self):
            pass

    # 3. Test Registration (DIR_REGISTER)
    print("[Step 1] Testing Registration...")
    node_data = {
        "node_id": "relay_node_01",
        "public_key": "aabbccdd" * 8,
        "address": "127.0.0.1",
        "port": 8081,
    }
    payload = json.dumps(node_data).encode("utf-8")

    # Manually trigger handler
    # We need to use the private handler method directly for unit testing
    # effectively simulating _process_command -> _handle_directory_register

    # Hack: Setup server mirror network known nodes manually to verify effect
    server.mirror_network.known_nodes = {}

    # Simulate receiving DIR_REGISTER command
    # Note: We can't easily call the private method _handle_directory_register directly without mocking more
    # So we will test the logic by creating a connection handler instance or similar?
    # Easier: Just manually verify the logic works by instantiating the handler

    from sush.server import ConnectionHandler

    mock_reader = asyncio.StreamReader()
    mock_writer = MockWriter()

    handler = ConnectionHandler(server, mock_reader, mock_writer, "127.0.0.1")

    await handler._handle_directory_register(payload)

    if b"DIR_OK:Registered" in mock_writer.data:
        print("PASS: Registration response received")
    else:
        print(f"FAIL: Registration failed. Response: {mock_writer.data}")
        sys.exit(1)

    # Check if node is actually in memory
    if "relay_node_01" in server.mirror_network.known_nodes:
        print("PASS: Node found in internal memory")
    else:
        print("FAIL: Node NOT found in internal memory")
        sys.exit(1)

    # 4. Test Fetch (DIR_FETCH)
    print("[Step 2] Testing Fetch...")
    mock_writer.data = b""  # Reset buffer

    await handler._handle_directory_fetch()

    if b"DIR_LIST:" in mock_writer.data:
        print("PASS: Directory list response received")
        # Parse response
        parts = mock_writer.data.split(b"DIR_LIST:", 1)
        parts[0][-4:]  # It sends length first in _send_data?
        # Actually _send_data prepends length(4) then data.
        # So mock_writer.data = LEN(4) + b"DIR_LIST:" + JSON

        # Let's just look for the JSON part
        response_str = mock_writer.data.decode(errors="ignore")
        if "relay_node_01" in response_str:
            print("PASS: Node ID found in directory listing")
        else:
            print(f"FAIL: Node ID missing from listing. Got: {response_str}")
            sys.exit(1)
    else:
        print(f"FAIL: No DIR_LIST prefix. Got: {mock_writer.data}")
        sys.exit(1)

    print("--- TEST SUCCESSFUL ---")


if __name__ == "__main__":
    asyncio.run(test_directory_flow())
