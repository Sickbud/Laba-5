import unittest
import os
import random
from rc5_core import RC5Algorithm
from rc5_file_utils import encrypt_file, decrypt_file

class TestRC5(unittest.TestCase):
    def test_block_encryption_decryption(self):
        key = b'1234567890123456'
        rc5 = RC5Algorithm(key)
        
        plaintext = b'testblck'
        ciphertext = rc5.encrypt_block(plaintext)
        self.assertNotEqual(plaintext, ciphertext)
        
        decrypted = rc5.decrypt_block(ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_file_encryption_decryption(self):
        key = b'1234567890123456'
        
        input_data = os.urandom(50)
        with open('test_input.bin', 'wb') as f:
            f.write(input_data)
            
        encrypt_file('test_input.bin', 'test_encrypted.bin', key)
        decrypt_file('test_encrypted.bin', 'test_decrypted.bin', key)
        
        with open('test_decrypted.bin', 'rb') as f:
            decrypted_data = f.read()
            
        self.assertEqual(input_data, decrypted_data)
        
        os.remove('test_input.bin')
        os.remove('test_encrypted.bin')
        os.remove('test_decrypted.bin')

    def test_file_encryption_exact_block_size(self):
        key = b'1234567890123456'
        
        input_data = os.urandom(16)
        with open('test_input_exact.bin', 'wb') as f:
            f.write(input_data)
            
        encrypt_file('test_input_exact.bin', 'test_encrypted_exact.bin', key)
        decrypt_file('test_encrypted_exact.bin', 'test_decrypted_exact.bin', key)
        
        with open('test_decrypted_exact.bin', 'rb') as f:
            decrypted_data = f.read()
            
        self.assertEqual(input_data, decrypted_data)
        
        os.remove('test_input_exact.bin')
        os.remove('test_encrypted_exact.bin')
        os.remove('test_decrypted_exact.bin')

if __name__ == '__main__':
    unittest.main()
