# blockchain_interface.py

import json
import logging
from web3 import Web3
from web3.exceptions import ContractLogicError, Web3ValidationError
from threading import Lock
import time
import os  # For environment variables
from eth_account import Account  # Import Account from eth_account
from dotenv import load_dotenv  # Import dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logger for this module
logger = logging.getLogger('secure_chat.blockchain_interface')
logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed logs
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class BlockchainInterface:
    def __init__(self):
        self.logger = logger
        self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # Replace with your blockchain URL
        if not self.w3.is_connected():
            self.logger.error("Failed to connect to the blockchain.")
            raise ConnectionError("Failed to connect to the blockchain.")

        # Load contract ABI and address
        abi_path = 'C:\\Users\\RTX\\Desktop\\test\\python\\blockchain\\MessageContractABI.json'
        try:
            with open(abi_path) as f:
                self.abi = json.load(f)
            self.logger.info(f"Loaded contract ABI from {abi_path}")
        except FileNotFoundError:
            self.logger.error(f"Contract ABI file not found at {abi_path}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decoding ABI JSON: {e}")
            raise

        contract_address = '0x8981129316b2e624D01011052613C94Ad750B11A'  # Replace with your contract address
        try:
            self.contract = self.w3.eth.contract(address=contract_address, abi=self.abi)
            self.logger.info(f"Contract instance created at address {contract_address}")
        except Exception as e:
            self.logger.error(f"Failed to create contract instance: {e}")
            raise

        # Set default account (ensure your private key is securely stored)
        private_key = os.getenv('BLOCKCHAIN_PRIVATE_KEY')  # Fetch from environment variable
        if not private_key:
            self.logger.error("Private key not provided for blockchain account. Set the BLOCKCHAIN_PRIVATE_KEY environment variable.")
            raise ValueError("Private key must be provided via BLOCKCHAIN_PRIVATE_KEY environment variable.")
        try:
            # Ensure the private key starts with '0x'
            if not private_key.startswith('0x'):
                private_key = '0x' + private_key
            self.account = Account.from_key(private_key)
            self.w3.eth.default_account = self.account.address
            self.logger.info(f"Default account set to {self.account.address}")
        except ValueError as ve:
            self.logger.error(f"Invalid private key format: {ve}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to set default account: {e}")
            raise

        self._lock = Lock()

    def log_message(self, message_hash: str):
        """
        Logs a message hash to the blockchain by calling the contract's logMessage function.

        :param message_hash: The SHA-256 hash of the message as a hex string.
        :return: Transaction receipt.
        """
        if not isinstance(message_hash, str):
            self.logger.error(f"Invalid message_hash: {message_hash}, type: {type(message_hash)}")
            raise ValueError("message_hash must be a string")

        try:
            with self._lock:
                # Fetch current nonce
                nonce = self.w3.eth.get_transaction_count(self.account.address, 'pending')
                self.logger.debug(f"Current nonce: {nonce}")

                # Fetch current gas price
                gas_price = self.w3.eth.gas_price
                self.logger.debug(f"Current gas price: {gas_price}")

                # Estimate gas
                try:
                    gas_estimate = self.contract.functions.logMessage(message_hash).estimate_gas(
                        {'from': self.account.address})
                    self.logger.debug(f"Estimated gas: {gas_estimate}")
                except ContractLogicError as e:
                    self.logger.error(f"Contract logic error during gas estimation: {e}")
                    raise

                # Build the transaction
                transaction = self.contract.functions.logMessage(message_hash).build_transaction({
                    'from': self.account.address,
                    'nonce': nonce,
                    'gas': gas_estimate,
                    'gasPrice': gas_price
                })
                self.logger.info(f"Transaction built: {transaction}")

                # Sign the transaction
                signed_txn = self.account.sign_transaction(transaction)
                self.logger.info("Transaction signed")

                # **Corrected Attribute Access: Use 'raw_transaction' instead of 'rawTransaction'**
                tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                self.logger.info(f"Transaction sent with hash: {tx_hash.hex()}")

                # Wait for the transaction receipt
                tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                if tx_receipt.status != 1:
                    self.logger.error("Transaction failed.")
                    raise Exception("Transaction failed.")

                self.logger.info(f"Transaction mined in block {tx_receipt.blockNumber}")

                # Process and verify the emitted event
                for log in tx_receipt.logs:
                    try:
                        event = self.contract.events.MessageLogged().process_log(log)  # Correct method name
                        emitted_hash = event['args']['messageHash']
                        self.logger.info(f"Event emitted: {emitted_hash}")
                        if emitted_hash == message_hash:
                            self.logger.info("Event hash matches the sent hash.")
                        else:
                            self.logger.warning("Event hash does not match the sent hash.")
                    except Exception as e:
                        self.logger.debug(f"Log processing error: {e}")

            # Introduce a 3-second delay
            time.sleep(3)

            return tx_receipt
        except Web3ValidationError as e:
            self.logger.error(f"Web3 Validation Error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error logging message to blockchain: {e}", exc_info=True)
            raise

    def get_past_messages(self, from_block=0) -> list:
        """
        Retrieves all past message hashes that have been logged to the blockchain.

        :param from_block: Block number to start fetching from.
        :return: List of message hashes as hex strings.
        """
        try:
            event_filter = self.contract.events.MessageLogged.createFilter(fromBlock=from_block, toBlock='latest')
            events = event_filter.get_all_entries()
            message_hashes = [event['args']['messageHash'] for event in events]
            self.logger.info(f"Retrieved {len(message_hashes)} message hashes from blockchain.")
            return message_hashes  # List of strings
        except Exception as e:
            self.logger.error(f"Error retrieving past messages from blockchain: {e}")
            raise

    def verify_message(self, message_hash: str) -> bool:
        """
        Verifies if a given message hash exists on the blockchain.

        :param message_hash: The SHA-256 hash of the message as a hex string.
        :return: True if exists, False otherwise.
        """
        try:
            self.logger.debug(f"Verifying message hash: {message_hash}")
            message_hashes = self.get_past_messages()
            self.logger.debug(f"Retrieved message hashes: {message_hashes}")

            if message_hash in message_hashes:
                self.logger.info("Message hash verified on the blockchain.")
                return True
            else:
                self.logger.warning("Message hash not found on the blockchain.")
                return False
        except Exception as e:
            self.logger.error(f"Error verifying message hash: {e}", exc_info=True)
            raise
