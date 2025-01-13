# Find Bitcoin Private Keys

This Python script identifies and saves private keys linked to Bitcoin addresses with balances or transactions.

## Features

-   Automatically decodes WIF (Wallet Import Format) private keys into their hexadecimal format.
-   Supports multiple Bitcoin address types: P2PKH (Uncompressed), P2PKH (Compressed), P2SH, and P2WPKH.
-   Retrieves real-time balance and transaction data using the Blockchain API.
-   Deduces and sorts the found private keys to ensure uniqueness and organization.

## Requirements

-   Python 3.x

## Usage

### 1. Prepare the Input File

Create a file named `input_bitcoin_private_keys.txt`. This file should contain Bitcoin private keys, either in WIF (Wallet Import Format) or hexadecimal format with each private key listed on a new line.

### 2. Install Dependencies

If you haven't installed the required dependencies, run the following command to install them:

```bash
pip install -r requirements.txt
```

### 3. Run the Script

Execute the Python script by running the following command:

```bash
python find_bitcoin_private_keys.py
```

### 4. Output

Once the script completes, it will generate a file named `found_bitcoin_private_keys.txt`. This file will contain the private keys linked to Bitcoin addresses with a balance or transaction history.
