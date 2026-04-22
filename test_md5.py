import unittest
import os
from md5_core import MD5Hasher
from md5_file_utils import calculateFileMd5, saveHashToFile, loadHashFromFile, verifyFileIntegrity

class TestMD5(unittest.TestCase):
    def setUp(self):
        self.hasher = MD5Hasher()
        self.test_file_path = "test_data.txt"
        self.test_hash_path = "test_data.md5"

    def tearDown(self):
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        if os.path.exists(self.test_hash_path):
            os.remove(self.test_hash_path)

    def test_rfc_empty_string(self):
        self.assertEqual(self.hasher.hashString(""), "D41D8CD98F00B204E9800998ECF8427E")

    def test_rfc_a(self):
        self.assertEqual(self.hasher.hashString("a"), "0CC175B9C0F1B6A831C399E269772661")

    def test_rfc_abc(self):
        self.assertEqual(self.hasher.hashString("abc"), "900150983CD24FB0D6963F7D28E17F72")
        
    def test_rfc_message_digest(self):
        self.assertEqual(self.hasher.hashString("message digest"), "F96B697D7CB7938D525A2F31AAF161D0")
        
    def test_rfc_alphabet(self):
        self.assertEqual(self.hasher.hashString("abcdefghijklmnopqrstuvwxyz"), "C3FCD3D76192E4007DFB496CCA67E13B")
    
    def test_rfc_alphabet(self):
        self.assertEqual(self.hasher.hashString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), "D174AB98D277D9F5A5611C2C9F419D9F")

    def test_rfc_alphabet(self):
        self.assertEqual(self.hasher.hashString("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), "57EDF4A22BE3C955AC49DA2E2107B67A")

    def test_file_hashing_and_integrity(self):
        test_content = "This is a test file content for MD5 hashing."
        with open(self.test_file_path, "w", encoding="utf-8") as f:
            f.write(test_content)
            
        expected_hash = self.hasher.hashString(test_content)
        
        file_hash = calculateFileMd5(self.test_file_path)
        self.assertEqual(file_hash, expected_hash)
        
        saveHashToFile(file_hash, self.test_hash_path)
        loaded_hash = loadHashFromFile(self.test_hash_path)
        self.assertEqual(loaded_hash, expected_hash)
        
        self.assertTrue(verifyFileIntegrity(self.test_file_path, self.test_hash_path))
        
        with open(self.test_file_path, "w", encoding="utf-8") as f:
            f.write("Modified content.")
            
        self.assertFalse(verifyFileIntegrity(self.test_file_path, self.test_hash_path))

if __name__ == "__main__":
    unittest.main()
