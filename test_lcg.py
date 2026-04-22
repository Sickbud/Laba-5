import unittest

try:
    from linear_congruential_generator import LinearCongruentialGenerator
except ModuleNotFoundError:
    from Lab1.linear_congruential_generator import LinearCongruentialGenerator

try:
    from math_utils import gcd
    from lcg_analysis import calculatePeriod, cesaroTest
except ModuleNotFoundError:
    from Lab1.math_utils import gcd
    from Lab1.lcg_analysis import calculatePeriod, cesaroTest


class TestLCG(unittest.TestCase):

    def setUp(self):
        self.modulus = 2 ** 11 - 1
        self.multiplier = 35
        self.increment = 1
        self.seed = 4
        self.gen = LinearCongruentialGenerator(
            self.modulus,
            self.multiplier,
            self.increment,
            self.seed
        )

    def testGenerateCount(self):
        numbers = self.gen.generate(5)
        self.assertEqual(len(numbers), 5)

    def testGcd(self):
        self.assertEqual(gcd(9, 28), 1)
        self.assertEqual(gcd(12, 8), 4)

    def testPeriodPositive(self):
        period = calculatePeriod(self.gen)
        self.assertTrue(period > 0)

    def testCesaroOutput(self):
        numbers = self.gen.generate(2000)
        probability, piEstimate = cesaroTest(numbers)
        self.assertTrue(0 < probability <= 1)
        self.assertTrue(piEstimate > 0)


if __name__ == "__main__":
    unittest.main()