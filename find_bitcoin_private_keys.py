import hashlib, base58, requests, time, sys
from ecdsa import SigningKey, SECP256k1
from bech32 import encode

INPUT_FILE = "input_bitcoin_private_keys.txt"
OUTPUT_FILE = "found_bitcoin_private_keys.txt"
BATCH_LIMIT = 100
FETCH_RETRY = 3
FETCH_DELAY = 30

found_private_keys = set()
unique_private_keys = set()
total_unique_private_keys = 0

def decode_wif_private_key(wif_private_key):
	"""Decode WIF (Wallet Import Format) private key to hexadecimal private key"""
	try:
		decoded = base58.b58decode(wif_private_key)
		private_key = decoded[1:-4]
		if len(private_key) == 33 and private_key[-1] == 0x01:
			private_key = private_key[:-1]
		return private_key.hex()
	except Exception:
		print(f"\033[2K\033[0G\033[1;107m Find Bitcoin Private Keys \033[0m\033[1;101m Error:\033[0m\033[91m Failed to decode WIF private key ({wif_private_key})\033[0m")
		sys.exit(1)

def generate_addresses_from_private_keys(private_keys):
	"""Generate public addresses from private keys and organize them into a dictionary, where each private key is mapped to its corresponding public addresses"""
	private_keys_with_public_addresses = []

	for private_key in private_keys:
		sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)

		uncompressed_public_key = b"\x04" + sk.get_verifying_key().pubkey.point.x().to_bytes(32, "big") + sk.get_verifying_key().pubkey.point.y().to_bytes(32, "big")
		compressed_public_key = (b"\x02" if sk.get_verifying_key().pubkey.point.y() % 2 == 0 else b"\x03") + sk.get_verifying_key().pubkey.point.x().to_bytes(32, "big")

		uncompressed_ripemd160 = hashlib.new("ripemd160", hashlib.sha256(uncompressed_public_key).digest()).digest()
		compressed_ripemd160 = hashlib.new("ripemd160", hashlib.sha256(compressed_public_key).digest()).digest()

		public_addresses = {
			base58.b58encode(b"\x00" + uncompressed_ripemd160 + hashlib.sha256(hashlib.sha256(b"\x00" + uncompressed_ripemd160).digest()).digest()[:4]).decode("utf-8"),
			base58.b58encode(b"\x00" + compressed_ripemd160 + hashlib.sha256(hashlib.sha256(b"\x00" + compressed_ripemd160).digest()).digest()[:4]).decode("utf-8"),
			base58.b58encode(b"\x05" + hashlib.new("ripemd160", hashlib.sha256(b"\x00\x14" + compressed_ripemd160).digest()).digest() + hashlib.sha256(hashlib.sha256(b"\x05" + hashlib.new("ripemd160", hashlib.sha256(b"\x00\x14" + compressed_ripemd160).digest()).digest()).digest()).digest()[:4]).decode("utf-8"),
			encode("bc", 0, compressed_ripemd160)
		}

		private_keys_with_public_addresses.append({private_key: public_addresses})

	return private_keys_with_public_addresses

def fetch_addresses_info(public_addresses, retries, delay):
	"""Fetch balance and transaction information from Blockchain API"""
	url = "https://blockchain.info/balance?active=" + "|".join(public_addresses)
	for attempt in range(retries):
		try:
			response = requests.get(url)
			response.raise_for_status()
			return response.json()
		except requests.RequestException:
			print(f"\033[2K\033[0G\033[1;107m Find Bitcoin Private Keys \033[0m\033[1;101m Error:\033[0m\033[91m Failed to fetch info for addresses (attempt {attempt + 1}/{retries})\033[0m")
			if attempt < retries - 1:
				time.sleep(delay)
			else:
				return {}

def save_unprocessed_private_keys(input_file):
	"""Save unprocessed private keys to input file"""
	global unique_private_keys
	with open(input_file, "w") as file:
		for private_key in list(unique_private_keys):
			file.write(f"{private_key}\n")

def dedupe_and_sort_output(output_file):
	"""Remove duplicates and sort the output file contents"""
	with open(output_file, "r") as file:
		lines = file.readlines()
	unique_lines = sorted(set(line.strip().upper() for line in lines if line.strip()))
	with open(output_file, "w") as file:
		file.write("\n".join(unique_lines) + "\n")

def process_public_addresses(private_keys_with_public_addresses, input_file, output_file, fetch_retry=3, fetch_delay=20):
	"""Process public addresses found from private keys"""
	global total_unique_private_keys, unique_private_keys
	all_public_addresses = []

	for key_pair in private_keys_with_public_addresses:
		for public_addresses in key_pair.values():
			filtered_public_addresses = [address for address in public_addresses if "charts" not in address.lower()]
			all_public_addresses.extend(filtered_public_addresses)

	all_public_addresses_info = fetch_addresses_info(all_public_addresses, fetch_retry, fetch_delay)

	if not all_public_addresses_info:
		print(f"\033[2K\033[0G\033[1;107m Find Bitcoin Private Keys \033[0m\033[1;101m Error:\033[0m\033[91m Exiting...\033[0m")
		save_unprocessed_private_keys(input_file)
		dedupe_and_sort_output(output_file)
		sys.exit(1)

	for public_address, data in all_public_addresses_info.items():
		private_key = next(private_key for key_pair in private_keys_with_public_addresses for private_key, public_addresses in key_pair.items() if public_address in public_addresses)
		print(f"\033[1;107m Find Bitcoin Private Keys \033[0m\033[1;100m Search:\033[0m {private_key} | Searched: [{total_unique_private_keys - len(unique_private_keys)} / {total_unique_private_keys}]", end="\r")
		if data["n_tx"] > 0:
			found_prefix = "\033[1;103m Found:\033[0m\033[93m" if data["final_balance"] > 0 else "\033[1;102m Found:\033[0m\033[92m"
			print(f"\033[2K\033[1;107m Find Bitcoin Private Keys \033[0m{found_prefix} {private_key} | {public_address} | Transactions: {data['n_tx']}, Balance: {data['final_balance']}\033[0m")
			if private_key not in found_private_keys:
				found_private_keys.add(private_key)
				with open(output_file, "a") as file:
					file.write(f"{private_key}\n")

def find_and_process_private_keys(input_file, output_file, batch_limit, fetch_retry, fetch_delay):
	"""Main function to process private keys and find addresses with balances or transactions"""
	global total_unique_private_keys, unique_private_keys

	try:
		with open(output_file, "r") as found:
			found_private_keys.update(found.read().strip().split("\n"))
	except FileNotFoundError:
		pass

	try:
		print(f"\033[1;107m Find Bitcoin Private Keys \033[0m\033[1;100m Input:\033[0m Processing {input_file} ...\033[0m", end="\r")
		with open(input_file, "r") as file:
			for private_key in file:
				private_key = private_key.strip()
				if len(private_key) in {51, 52}:
					private_key = decode_wif_private_key(private_key)
				unique_private_keys.add(private_key.upper())
		unique_private_keys.difference_update(found_private_keys)
		total_unique_private_keys = len(unique_private_keys)
		save_unprocessed_private_keys(input_file)
	except FileNotFoundError:
		print(f"\033[2K\033[0G\033[1;107m Find Bitcoin Private Keys \033[0m\033[1;101m Error:\033[0m\033[91m Input file {input_file} not found!\033[0m")
		sys.exit(1)

	while unique_private_keys:
		private_keys = list(unique_private_keys)[:batch_limit]
		private_keys_with_public_addresses = generate_addresses_from_private_keys(private_keys)
		process_public_addresses(private_keys_with_public_addresses, input_file, output_file, fetch_retry, fetch_delay)
		unique_private_keys.difference_update(private_keys)

	save_unprocessed_private_keys(input_file)
	dedupe_and_sort_output(output_file)

	print("\033[2K\033[0G", end="")

if __name__ == "__main__":
	try:
		find_and_process_private_keys(INPUT_FILE, OUTPUT_FILE, BATCH_LIMIT, FETCH_RETRY, FETCH_DELAY)
	except KeyboardInterrupt:
		print(f"\033[2K\033[0G\033[1;107m Find Bitcoin Private Keys \033[0m\033[1;101m Error:\033[0m\033[91m KeyboardInterrupt! Exiting...\033[0m")
		save_unprocessed_private_keys(INPUT_FILE)
		dedupe_and_sort_output(OUTPUT_FILE)
		sys.exit(1)
