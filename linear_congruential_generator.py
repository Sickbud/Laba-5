class LinearCongruentialGenerator:
    def __init__(self, modulus, multiplier, increment, seed):
        self.modulus = modulus
        self.multiplier = multiplier
        self.increment = increment
        self.seed = seed

    def generate(self, count):
        numbers = []
        x = self.seed
        for _ in range(count):
            x = (self.multiplier * x + self.increment) % self.modulus
            numbers.append(x)
        return numbers
