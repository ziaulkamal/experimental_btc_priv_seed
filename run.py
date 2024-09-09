import os
import json
import requests
import base58
import hashlib
from ecdsa import SigningKey, SECP256k1
from mnemonic import Mnemonic
from bip_utils import Bip44, Bip44Coins, Bip44Changes, Bip39SeedGenerator
from Crypto.Hash import RIPEMD160
from multiprocessing import Pool, cpu_count

# Konfigurasi API BlockCypher
BLOCKCYPHER_API_URL = 'https://api.blockcypher.com/v1/btc/main/addrs/'

# Buat folder output jika belum ada
output_dir = "output"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Baca API key dari file
def load_api_keys(filepath='apikey.txt'):
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

api_keys = load_api_keys()
api_key_index = 0

def generate_bitcoin_data():
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)
    seed = Bip39SeedGenerator(mnemonic_phrase).Generate()
    bip44_ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)
    bip44_acc = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
    address_index_0 = bip44_acc.AddressIndex(0)
    btc_address_bip44 = address_index_0.PublicKey().ToAddress()

    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    public_key_bytes = b'\x02' + public_key.to_string()[:32] if public_key.to_string()[63] % 2 == 0 else b'\x03' + public_key.to_string()[:32]
    sha256_1 = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = RIPEMD160.new(sha256_1).digest()
    hashed_public_key = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()[:4]
    btc_address_secp256k1 = base58.b58encode(hashed_public_key + checksum).decode('utf-8')
    private_key_hex = private_key.to_string().hex()

    return {
        "address_bip44": btc_address_bip44,
        "address_secp256k1": btc_address_secp256k1,
        "private_key": private_key_hex,
        "mnemonic_phrase": mnemonic_phrase
    }

def get_balance(address):
    global api_key_index
    api_key = api_keys[api_key_index]
    api_key_index = (api_key_index + 1) % len(api_keys)
    
    url = f'{BLOCKCYPHER_API_URL}{address}/balance'
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data['final_balance']
    except requests.exceptions.RequestException as e:
        print(f"Error fetching balance for {address} with API key {api_key}: {e}")
        return None

def save_to_json(data, address):
    filename = f"{output_dir}/{address}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Data saved to {filename}")

def process_address(index):
    bitcoin_data = generate_bitcoin_data()
    address = bitcoin_data['address_bip44']
    balance = get_balance(address)
    if balance is not None and balance > 0:
        print(f"Address {address} has balance: {balance} satoshis.")
        save_to_json(bitcoin_data, address)
    else:
        print(f"Address {address} has no balance or could not be fetched.")

def generate_and_check_multiple_data_parallel(count, num_cores):
    with Pool(processes=num_cores) as pool:
        pool.map(process_address, range(count))

if __name__ == '__main__':
    count = int(input("Enter how many addresses you want to generate: "))
    max_cores = cpu_count()
    print(f"Available CPU cores: {max_cores}")
    num_cores = int(input(f"Enter how many cores you want to use (1 to {max_cores}): "))
    
    if num_cores < 1 or num_cores > max_cores:
        print(f"Invalid number of cores. Please enter a number between 1 and {max_cores}.")
    else:
        generate_and_check_multiple_data_parallel(count, num_cores)
