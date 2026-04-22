import os
from md5_core import MD5Hasher

def calculateFileMd5(filePath: str) -> str:
    hasher = MD5Hasher()
    with open(filePath, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def saveHashToFile(hashValue: str, outputPath: str):
    with open(outputPath, 'w', encoding='utf-8') as f:
        f.write(hashValue)

def loadHashFromFile(hashFilePath: str) -> str:
    with open(hashFilePath, 'r', encoding='utf-8') as f:
        return f.read().strip()

def verifyFileIntegrity(filePath: str, hashFilePath: str) -> bool:
    if not os.path.exists(filePath) or not os.path.exists(hashFilePath):
        return False
    
    expected_hash = loadHashFromFile(hashFilePath)
    actual_hash = calculateFileMd5(filePath)
    
    return expected_hash.upper() == actual_hash.upper()