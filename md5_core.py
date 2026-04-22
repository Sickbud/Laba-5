import math

class MD5Hasher:
    # MD5 constants
    _T = [int((1 << 32) * abs(math.sin(i + 1))) & 0xFFFFFFFF for i in range(64)]
    _S = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ]

    @staticmethod
    def _left_rotate(x, c):
        x &= 0xFFFFFFFF
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def __init__(self):
        self._init_state()

    def _init_state(self):
        self.A = 0x67452301
        self.B = 0xefcdab89
        self.C = 0x98badcfe
        self.D = 0x10325476
        
        self._buffer = bytearray()
        self._total_length = 0

    def _process_chunk(self, chunk):
        w = [0] * 16
        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4:i * 4 + 4], byteorder='little')

        a, b, c, d = self.A, self.B, self.C, self.D

        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            f = (f + a + self._T[i] + w[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + self._left_rotate(f, self._S[i])) & 0xFFFFFFFF

        self.A = (self.A + a) & 0xFFFFFFFF
        self.B = (self.B + b) & 0xFFFFFFFF
        self.C = (self.C + c) & 0xFFFFFFFF
        self.D = (self.D + d) & 0xFFFFFFFF

    def update(self, data):
        self._buffer.extend(data)
        self._total_length += len(data)

        while len(self._buffer) >= 64:
            chunk = self._buffer[:64]
            self._process_chunk(chunk)
            self._buffer = self._buffer[64:]

    def _pad_and_finish(self):
        temp_A, temp_B, temp_C, temp_D = self.A, self.B, self.C, self.D
        temp_buffer = bytearray(self._buffer)
        
        temp_buffer.append(0x80)
        while len(temp_buffer) % 64 != 56:
            temp_buffer.append(0x00)

        bit_len = (self._total_length * 8) & 0xFFFFFFFFFFFFFFFF
        temp_buffer += bit_len.to_bytes(8, byteorder='little')

        for i in range(0, len(temp_buffer), 64):
            chunk = temp_buffer[i:i + 64]
            
            w = [0] * 16
            for j in range(16):
                w[j] = int.from_bytes(chunk[j * 4:j * 4 + 4], byteorder='little')

            a, b, c, d = temp_A, temp_B, temp_C, temp_D

            for k in range(64):
                if 0 <= k <= 15:
                    f = (b & c) | (~b & d)
                    g = k
                elif 16 <= k <= 31:
                    f = (d & b) | (~d & c)
                    g = (5 * k + 1) % 16
                elif 32 <= k <= 47:
                    f = b ^ c ^ d
                    g = (3 * k + 5) % 16
                elif 48 <= k <= 63:
                    f = c ^ (b | ~d)
                    g = (7 * k) % 16

                f = (f + a + self._T[k] + w[g]) & 0xFFFFFFFF
                rotated = self._left_rotate(f, self._S[k])
                a, d, c, b = d, c, b, (b + rotated) & 0xFFFFFFFF

            temp_A = (temp_A + a) & 0xFFFFFFFF
            temp_B = (temp_B + b) & 0xFFFFFFFF
            temp_C = (temp_C + c) & 0xFFFFFFFF
            temp_D = (temp_D + d) & 0xFFFFFFFF

        return b''.join(x.to_bytes(4, byteorder='little') for x in [temp_A, temp_B, temp_C, temp_D])

    def hexdigest(self):
        result = self._pad_and_finish()
        return ''.join(f'{b:02x}' for b in result).upper()

    def hashBytes(self, data: bytes) -> str:
        self._init_state()
        self.update(data)
        return self.hexdigest()

    def hashString(self, text: str) -> str:
        return self.hashBytes(text.encode('utf-8'))