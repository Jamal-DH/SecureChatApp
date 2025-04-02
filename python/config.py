# config.py

import os

server_port = 12345
client1_port = 12346
client2_port = 12347




current_dir = os.path.dirname(os.path.abspath(__file__))
blockchain_dir = os.path.join(current_dir, 'blockchain')

# Absolute path to the ABI file
abi_path = os.path.join(blockchain_dir, 'MessageContractABI.json')

BLOCKCHAIN = {
    'provider': 'http://127.0.0.1:7545',  # Your blockchain RPC URL (e.g., Ganache)
    'contract_address': '0x8981129316b2e624D01011052613C94Ad750B11A',  # New contract address
    'abi_path': abi_path,
    'default_account': '0x0ec0245cE6ca72B1bD743abE8E44dC8B8268A3B4',  # Your account address
}