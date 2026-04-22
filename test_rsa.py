import unittest
import os
from rsa_file_utils import generate_rsa_keys, encrypt_file_rsa, decrypt_file_rsa

class TestRSA(unittest.TestCase):
    def setUp(self):
        self.priv_key_path = 'test_priv_key.pem'
        self.pub_key_path = 'test_pub_key.pem'
        self.input_file = 'test_input.bin'
        self.enc_file = 'test_enc.bin'
        self.dec_file = 'test_dec.bin'

        generate_rsa_keys(self.priv_key_path, self.pub_key_path)

    def tearDown(self):
        for file in [self.priv_key_path, self.pub_key_path, self.input_file, self.enc_file, self.dec_file]:
            if os.path.exists(file):
                os.remove(file)

    def test_key_generation(self):
        self.assertTrue(os.path.exists(self.priv_key_path))
        self.assertTrue(os.path.exists(self.pub_key_path))
        
        self.assertGreater(os.path.getsize(self.priv_key_path), 0)
        self.assertGreater(os.path.getsize(self.pub_key_path), 0)

    def test_file_encryption_decryption_small(self):
        input_data = os.urandom(50)
        with open(self.input_file, 'wb') as f:
            f.write(input_data)
        
        encrypt_file_rsa(self.input_file, self.enc_file, self.pub_key_path)
        decrypt_file_rsa(self.enc_file, self.dec_file, self.priv_key_path)
        
        with open(self.dec_file, 'rb') as f:
            decrypted_data = f.read()
            
        self.assertEqual(input_data, decrypted_data)

    def test_file_encryption_decryption_large(self):
        input_data = os.urandom(300)
        with open(self.input_file, 'wb') as f:
            f.write(input_data)
        
        encrypt_file_rsa(self.input_file, self.enc_file, self.pub_key_path)
        decrypt_file_rsa(self.enc_file, self.dec_file, self.priv_key_path)
        
        with open(self.dec_file, 'rb') as f:
            decrypted_data = f.read()
            
        self.assertEqual(input_data, decrypted_data)


if __name__ == '__main__':
    unittest.main()
