# compile_contract.py

from solcx import compile_source, install_solc
import json
import os

# Install the required Solidity compiler version
install_solc('0.8.0')

# Set the path to the Solidity file
contract_file = os.path.join(os.path.dirname(__file__), 'MessageContract.sol')  # Adjust the path if necessary

# Read the Solidity contract source code
with open(contract_file, 'r') as file:
    contract_source_code = file.read()

# Compile the contract
compiled_sol = compile_source(
    contract_source_code,
    output_values=['abi', 'bin'],
    solc_version='0.8.0',
)

# Extract the contract interface
contract_id, contract_interface = compiled_sol.popitem()

# Ensure the output directory exists
output_dir = os.path.dirname(contract_file)
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Save the ABI to a JSON file
abi = contract_interface['abi']
abi_path = os.path.join(output_dir, 'MessageContractABI.json')
with open(abi_path, 'w') as abi_file:
    json.dump(abi, abi_file)

# Save the bytecode
bytecode = contract_interface['bin']
bytecode_path = os.path.join(output_dir, 'MessageContractBytecode.json')
with open(bytecode_path, 'w') as bytecode_file:
    json.dump(bytecode, bytecode_file)

print("Contract compiled successfully.")
print(f"ABI saved to: {abi_path}")
print(f"Bytecode saved to: {bytecode_path}")
