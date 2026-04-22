class RC5Algorithm:
    def __init__(self, key: bytes, w: int = 32, r: int = 12):
        self.w = w
        self.r = r
        self.b = len(key)
        self.mod = 2 ** w
        self.mask = self.mod - 1
        self.t = 2 * (r + 1)
        self._key_expansion(key)

    def rotl(self, x: int, y: int) -> int:
        # зсув вліво
        y = y % self.w
        if y == 0:
            return x & self.mask
        return ((x << y) | (x >> (self.w - y))) & self.mask

    def rotr(self, x: int, y: int) -> int:
        # вправо
        y = y % self.w
        if y == 0:
            return x & self.mask
        return ((x >> y) | (x << (self.w - y))) & self.mask

    def _key_expansion(self, key: bytes):
        u = self.w // 8
        c = max(1, (self.b + u - 1) // u)
        L = [0] * c
        
        if self.b > 0:
            for i in range(self.b - 1, -1, -1):
                L[i // u] = (L[i // u] << 8) + key[i]
                
        P32 = 0xB7E15163
        Q32 = 0x9E3779B9
        
        S = [0] * self.t
        S[0] = P32
        for i in range(1, self.t):
            S[i] = (S[i - 1] + Q32) % self.mod
            
        i = j = 0
        A = B = 0
        iterations = 3 * max(self.t, c)
        
        for _ in range(iterations):
            A = S[i] = self.rotl((S[i] + A + B) % self.mod, 3)
            B = L[j] = self.rotl((L[j] + A + B) % self.mod, A + B)
            i = (i + 1) % self.t
            j = (j + 1) % c
            
        self.S = S

    def encrypt_block(self, block: bytes) -> bytes:
        # шифрування блоку
        if len(block) != 2 * (self.w // 8):
            raise ValueError("Block size must be 2 * w bits")
        
        u = self.w // 8
        A = int.from_bytes(block[:u], byteorder='little')
        B = int.from_bytes(block[u:], byteorder='little')
        
        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod
        
        for i in range(1, self.r + 1):
            A = (self.rotl(A ^ B, B) + self.S[2 * i]) % self.mod
            B = (self.rotl(B ^ A, A) + self.S[2 * i + 1]) % self.mod
            
        return A.to_bytes(u, byteorder='little') + B.to_bytes(u, byteorder='little')

    def decrypt_block(self, block: bytes) -> bytes:
        # розшифрування блоку
        if len(block) != 2 * (self.w // 8):
            raise ValueError("Block size must be 2 * w bits")
            
        u = self.w // 8
        A = int.from_bytes(block[:u], byteorder='little')
        B = int.from_bytes(block[u:], byteorder='little')
        
        for i in range(self.r, 0, -1):
            B = self.rotr((B - self.S[2 * i + 1]) % self.mod, A) ^ A
            A = self.rotr((A - self.S[2 * i]) % self.mod, B) ^ B
            
        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod
        
        return A.to_bytes(u, byteorder='little') + B.to_bytes(u, byteorder='little')
