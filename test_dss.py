import unittest
import os
import tempfile

try:
    from dss_core import DSSigner
    from dss_file_utils import signFile, verifyFileSignature, saveSignatureToFile, loadSignatureFromFile
except ImportError:
    from Code.dss_core import DSSigner
    from Code.dss_file_utils import signFile, verifyFileSignature, saveSignatureToFile, loadSignatureFromFile

class TestDSS(unittest.TestCase):
    def setUp(self):
        self.signer = DSSigner()
        self.signer.generate_keys()
        
        self.test_dir = tempfile.TemporaryDirectory()
        self.priv_key_path = os.path.join(self.test_dir.name, "priv.pem")
        self.pub_key_path = os.path.join(self.test_dir.name, "pub.pem")
        self.file_path = os.path.join(self.test_dir.name, "test_file.txt")
        self.sig_path = os.path.join(self.test_dir.name, "test_file.sig")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_key_generation(self):
        self.signer.save_private_key(self.priv_key_path)
        self.signer.save_public_key(self.pub_key_path)
        self.assertTrue(os.path.exists(self.priv_key_path))
        self.assertTrue(os.path.exists(self.pub_key_path))
        self.assertGreater(os.path.getsize(self.priv_key_path), 0)
        self.assertGreater(os.path.getsize(self.pub_key_path), 0)

    def test_sign_and_verify_bytes(self):
        data = b"test message"
        signature = self.signer.sign_data(data)
        self.assertTrue(self.signer.verify_data(data, signature))

    def test_verify_wrong_data(self):
        data1 = b"test message 1"
        data2 = b"test message 2"
        signature = self.signer.sign_data(data1)
        self.assertFalse(self.signer.verify_data(data2, signature))

    def test_save_load_keys(self):
        self.signer.save_private_key(self.priv_key_path)
        self.signer.save_public_key(self.pub_key_path)
        
        data = b"hello world"
        original_signature = self.signer.sign_data(data)
        
        new_signer = DSSigner()
        new_signer.load_public_key(self.pub_key_path)
        self.assertTrue(new_signer.verify_data(data, original_signature))
        
        # Перевірка завантаження приватного ключа
        new_signer2 = DSSigner()
        new_signer2.load_private_key(self.priv_key_path)
        new_signature = new_signer2.sign_data(data)
        self.assertTrue(new_signer2.verify_data(data, new_signature))

    def test_file_sign_and_verify(self):
        # Створення тестового файлу
        with open(self.file_path, "w", encoding="utf-8") as f:
            f.write("Текстові дані для підпису")
        
        # Підпис
        hex_sig = signFile(self.file_path, self.sig_path, self.signer)
        
        # Перевірка існування файлу підпису
        self.assertTrue(os.path.exists(self.sig_path))
        
        # Перевірка підпису
        self.assertTrue(verifyFileSignature(self.file_path, self.sig_path, self.signer))

    def test_file_verify_tampered(self):
        with open(self.file_path, "w", encoding="utf-8") as f:
            f.write("Текстові дані для підпису")
            
        signFile(self.file_path, self.sig_path, self.signer)
        
        # Змінюємо дані
        with open(self.file_path, "w", encoding="utf-8") as f:
            f.write("Текстові дані для підпису - змінено")
            
        self.assertFalse(verifyFileSignature(self.file_path, self.sig_path, self.signer))

if __name__ == "__main__":
    unittest.main()
