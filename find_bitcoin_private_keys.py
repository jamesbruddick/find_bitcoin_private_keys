import hashlib
import base58
from ecdsa import SigningKey, SECP256k1
from bech32 import encode
import requests

def decode_wif_private_key(wif_private_key):
	"""Decode WIF to hexadecimal private key"""
	decoded = base58.b58decode(wif_private_key)
	private_key_data = decoded[1:-4]
	if len(private_key_data) == 33 and private_key_data[-1] == 0x01:
		private_key_data = private_key_data[:-1]
	return private_key_data.hex()

def generate_public_keys(private_key_hex):
	"""Generate both uncompressed and compressed public keys from private key"""
	sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)

	uncompressed_pubkey = b'\x04' + sk.get_verifying_key().pubkey.point.x().to_bytes(32, 'big') + sk.get_verifying_key().pubkey.point.y().to_bytes(32, 'big')
	compressed_pubkey = (b'\x02' if sk.get_verifying_key().pubkey.point.y() % 2 == 0 else b'\x03') + sk.get_verifying_key().pubkey.point.x().to_bytes(32, 'big')

	return uncompressed_pubkey, compressed_pubkey

def generate_addresses_from_public_keys(uncompressed_pubkey, compressed_pubkey):
	"""Generate multiple types of Bitcoin addresses from public keys"""
	ripemd160_uncompressed = hashlib.new('ripemd160', hashlib.sha256(uncompressed_pubkey).digest()).digest()
	ripemd160_compressed = hashlib.new('ripemd160', hashlib.sha256(compressed_pubkey).digest()).digest()

	addresses = {
		base58.b58encode(b'\x00' + ripemd160_uncompressed + hashlib.sha256(hashlib.sha256(b'\x00' + ripemd160_uncompressed).digest()).digest()[:4]).decode('utf-8'),
		base58.b58encode(b'\x00' + ripemd160_compressed + hashlib.sha256(hashlib.sha256(b'\x00' + ripemd160_compressed).digest()).digest()[:4]).decode('utf-8'),
		base58.b58encode(b'\x05' + hashlib.new('ripemd160', hashlib.sha256(b'\x00\x14' + ripemd160_compressed).digest()).digest() + hashlib.sha256(hashlib.sha256(b'\x05' + hashlib.new('ripemd160', hashlib.sha256(b'\x00\x14' + ripemd160_compressed).digest()).digest()).digest()).digest()[:4]).decode('utf-8'),
		encode("bc", 0, ripemd160_compressed)
	}
	return addresses

def fetch_address_info(public_addresses):
	"""Fetch balance and transaction information from Blockchain API"""
	url = "https://blockchain.info/balance?active=" + "|".join(public_addresses)
	try:
		response = requests.get(url)
		response.raise_for_status()
		return response.json()
	except requests.RequestException as e:
		print(f"Error fetching data for addresses: {e}")
		return {}

def process_found_keys(private_key, public_addresses, output_file):
	"""Process found private keys based on the address data"""
	address_data = fetch_address_info(public_addresses)

	for address, info in address_data.items():
		if info.get("final_balance", 0) > 0:
			print(f"Balance found at Address: {address}, Private Key: {private_key}, Balance: {info['final_balance']}")
			with open(output_file, 'a') as f:
				f.write(f"{private_key}\n")
			return
		elif info.get("n_tx", 0) > 0:
			print(f"Transactions found at Address: {address}, Private Key: {private_key}, Transactions: {info['n_tx']}")
			with open(output_file, 'a') as f:
				f.write(f"{private_key}\n")
			return

def dedupe_and_sort_output(output_file):
	"""Remove duplicates and sort the output file contents"""
	with open(output_file, 'r') as file:
		lines = file.readlines()

	unique_lines = sorted(set(line.strip().upper() for line in lines if line.strip()))
	
	with open(output_file, 'w') as file:
		file.write('\n'.join(unique_lines) + '\n')

def find_and_process_private_keys(input_file="input_bitcoin_private_keys.txt", output_file="found_bitcoin_private_keys.txt"):
	"""Main function to process private keys and find addresses with balances or transactions"""
	unique_private_keys = set()

	try:
		with open(output_file, 'r') as found:
			found_private_keys = set(found.read().strip().split('\n'))
	except FileNotFoundError:
		found_private_keys = set()

	with open(input_file, 'r') as input_file:
		for private_key in input_file:
			private_key = private_key.strip()
			if len(private_key) in {51, 52}:
				private_key = decode_wif_private_key(private_key)
			private_key = private_key.upper()
			if private_key not in found_private_keys:
				unique_private_keys.add(private_key)

	for private_key in unique_private_keys:
		uncompressed_pubkey, compressed_pubkey = generate_public_keys(private_key)
		public_addresses = generate_addresses_from_public_keys(uncompressed_pubkey, compressed_pubkey)
		process_found_keys(private_key, list(public_addresses), output_file)

	dedupe_and_sort_output(output_file)

if __name__ == "__main__":
	find_and_process_private_keys()
