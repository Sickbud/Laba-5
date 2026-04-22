import os
import random
from rc5_core import RC5Algorithm
from linear_congruential_generator import LinearCongruentialGenerator

BLOCK_SIZE = 8

def _pkcs7_pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)

def _generate_iv() -> bytes:
    gen = LinearCongruentialGenerator(2**11 - 1, 35, 1, random.randint(1, 1000))
    numbers = gen.generate(BLOCK_SIZE)
    return bytes([x % 256 for x in numbers])

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

def encrypt_file(input_path: str, output_path: str, key: bytes):
    rc5 = RC5Algorithm(key)
    iv = _generate_iv()
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(rc5.encrypt_block(iv))
        chain_block = iv
        
        while True:
            chunk = f_in.read(BLOCK_SIZE)
            if not chunk:
                pad_block = _pkcs7_pad(b"")
                xor_block = xor_bytes(pad_block, chain_block)
                f_out.write(rc5.encrypt_block(xor_block))
                break
            
            if len(chunk) < BLOCK_SIZE:
                pad_block = _pkcs7_pad(chunk)
                xor_block = xor_bytes(pad_block, chain_block)
                f_out.write(rc5.encrypt_block(xor_block))
                break
            
            pos = f_in.tell()
            next_byte = f_in.read(1)
            f_in.seek(pos)
            
            if not next_byte:
                xor_block = xor_bytes(chunk, chain_block)
                enc_block = rc5.encrypt_block(xor_block)
                f_out.write(enc_block)
                chain_block = enc_block
            else:
                xor_block = xor_bytes(chunk, chain_block)
                enc_block = rc5.encrypt_block(xor_block)
                f_out.write(enc_block)
                chain_block = enc_block


def decrypt_file(input_path: str, output_path: str, key: bytes):
    rc5 = RC5Algorithm(key)
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        first_block = f_in.read(BLOCK_SIZE)
        if len(first_block) < BLOCK_SIZE:
            raise ValueError("File is too short or corrupt.")
            
        iv = rc5.decrypt_block(first_block)
        chain_block = iv
        
        prev_chunk = f_in.read(BLOCK_SIZE)
        if not prev_chunk:
            return  
            
        while True:
            next_chunk = f_in.read(BLOCK_SIZE)
            
            dec_block = rc5.decrypt_block(prev_chunk)
            plain_block = xor_bytes(dec_block, chain_block)
            chain_block = prev_chunk
            
            if not next_chunk:
                pad_len = plain_block[-1]
                if 0 < pad_len <= BLOCK_SIZE:
                    plain_block = plain_block[:-pad_len]
                f_out.write(plain_block)
                break
            else:
                f_out.write(plain_block)
                prev_chunk = next_chunk
