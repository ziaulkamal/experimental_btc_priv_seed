import hashlib
import base58
import os
import json
from ecdsa import SigningKey, SECP256k1
from mnemonic import Mnemonic
from bip_utils import Bip44, Bip44Coins, Bip44Changes, Bip39SeedGenerator

# Buat folder output jika belum ada
output_dir = "output"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Fungsi untuk generate Bitcoin address, private key, dan mnemonic phrase
def generate_bitcoin_data():
    # Generate a 12-word mnemonic using BIP39
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)

    # Generate seed from mnemonic
    seed = Bip39SeedGenerator(mnemonic_phrase).Generate()

    # Initialize BIP44 for Bitcoin mainnet
    bip44_ctx = Bip44.FromSeed(seed, Bip44Coins.BITCOIN)

    # Derive account 0, external chain (for receiving addresses), and address index 0
    bip44_acc = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT)
    address_index_0 = bip44_acc.AddressIndex(0)

    # Get the Bitcoin address from BIP44 derivation path
    btc_address_bip44 = address_index_0.PublicKey().ToAddress()

    # Additional: Generate private key using secp256k1 and derive public key
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()

    # Convert public key to compressed format
    public_key_bytes = b'\x02' + public_key.to_string()[:32] if public_key.to_string()[63] % 2 == 0 else b'\x03' + public_key.to_string()[:32]

    # Bitcoin address generation (Base58Check encoding) from secp256k1 public key
    sha256_1 = hashlib.sha256(public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_1).digest()
    hashed_public_key = b'\x00' + ripemd160  # 0x00 is the prefix for a mainnet Bitcoin address

    # Perform double SHA-256 hashing
    checksum = hashlib.sha256(hashlib.sha256(hashed_public_key).digest()).digest()[:4]

    # Final address (secp256k1 generated address)
    btc_address_secp256k1 = base58.b58encode(hashed_public_key + checksum).decode('utf-8')

    # Convert private key to hexadecimal format
    private_key_hex = private_key.to_string().hex()

    # Return a dictionary of data
    return {
        "address_bip44": btc_address_bip44,
        "address_secp256k1": btc_address_secp256k1,
        "private_key": private_key_hex,
        "mnemonic_phrase": mnemonic_phrase
    }

# Fungsi untuk menyimpan data ke dalam file JSON
def save_to_json(data, address):
    filename = f"{output_dir}/{address}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Data saved to {filename}")

# Fungsi utama untuk generate banyak data
def generate_multiple_data(count):
    for i in range(count):
        bitcoin_data = generate_bitcoin_data()
        # Save the data with the address as the filename
        save_to_json(bitcoin_data, bitcoin_data['address_bip44'])

# Input jumlah data yang ingin di-generate
count = int(input("Enter how many addresses you want to generate: "))

# Generate dan simpan data
generate_multiple_data(count)
