import json
import os
from web3 import Web3

RPC_URL = "http://127.0.0.1:8545"
ARTIFACT_PATH = os.path.join("artifacts", "contracts", "LogVault.sol", "LogVault.json")
OUTPUT_PATH = "contract_address.txt"

def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))

    if not w3.is_connected():
        print("ERROR: Could not connect to local blockchain at " + RPC_URL)
        print("Make sure 'npx hardhat node' is running in another terminal.")
        return

    with open(ARTIFACT_PATH, "r") as f:
        artifact = json.load(f)

    abi = artifact["abi"]
    bytecode = artifact["bytecode"]

    deployer = w3.eth.accounts[0]
    print("Deploying from account:", deployer)

    Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = Contract.constructor().transact({"from": deployer})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    contract_address = receipt.contractAddress
    print("Contract deployed at:", contract_address)

    with open(OUTPUT_PATH, "w") as f:
        f.write(contract_address)

    print("Address saved to", OUTPUT_PATH)

if __name__ == "__main__":
    main()
