# deploy_contract.py

from web3 import Web3
import json
import os
import sys


parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Add the parent directory to sys.path
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from config import BLOCKCHAIN

# Connect to the blockchain
w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN['provider']))

# Load the ABI and bytecode
with open(BLOCKCHAIN['abi_path'], 'r') as abi_file:
    abi = json.load(abi_file)

bytecode_path = os.path.join(os.path.dirname(BLOCKCHAIN['abi_path']), 'MessageContractBytecode.json')
with open(bytecode_path, 'r') as bytecode_file:
    bytecode = json.load(bytecode_file)

# Set the default account
w3.eth.default_account = BLOCKCHAIN['default_account']

# Create the contract in Python
MessageContract = w3.eth.contract(abi=abi, bytecode=bytecode)

# Submit the transaction that deploys the contract
tx_hash = MessageContract.constructor().transact()

# Wait for the transaction to be mined
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Get the contract address
contract_address = tx_receipt.contractAddress
print(f'Contract deployed at address: {contract_address}')

# Update the contract address in config.py
# Optionally, you can write this back to config.py or just note it down
