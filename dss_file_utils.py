import os
from dss_core import DSSigner
from md5_file_utils import calculateFileMd5

def signFile(filePath: str, signatureOutputPath: str, signer: DSSigner) -> str:
    # Обчислюємо MD5 хеш файлу
    hex_hash = calculateFileMd5(filePath)
    
    # Підписуємо байти хешу
    signature = signer.sign_data(hex_hash.encode('utf-8'))
    
    # Зберігаємо підпис
    hex_signature = signature.hex().upper()
    saveSignatureToFile(signature, signatureOutputPath)
    
    return hex_signature

def verifyFileSignature(filePath: str, signatureFilePath: str, signer: DSSigner) -> bool:
    if not os.path.exists(filePath) or not os.path.exists(signatureFilePath):
        return False
        
    # Обчислюємо MD5 хеш файлу
    hex_hash = calculateFileMd5(filePath)
    
    # Зчитуємо підпис
    signatureBytes = loadSignatureFromFile(signatureFilePath)
    
    # Перевіряємо підпис
    return signer.verify_data(hex_hash.encode('utf-8'), signatureBytes)

def saveSignatureToFile(signature: bytes, outputPath: str):
    with open(outputPath, 'w', encoding='utf-8') as f:
        f.write(signature.hex().upper())

def loadSignatureFromFile(signaturePath: str) -> bytes:
    with open(signaturePath, 'r', encoding='utf-8') as f:
        hex_signature = f.read().strip()
    return bytes.fromhex(hex_signature)
