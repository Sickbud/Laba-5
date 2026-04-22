from math_utils import gcd


def calculatePeriod(generator):
    x = (generator.multiplier * generator.seed + generator.increment) % generator.modulus
    period = 1
    while x != generator.seed:
        x = (generator.multiplier * x + generator.increment) % generator.modulus
        period += 1
        if period > generator.modulus:
            break
    return period


def cesaroTest(numbers):
    pairsCount = 0
    coprimeCount = 0
    length = len(numbers)
    for i in range(0, length - 1, 2):
        a = numbers[i]
        b = numbers[i + 1]
        pairsCount += 1
        if gcd(a, b) == 1:
            coprimeCount += 1
    if pairsCount == 0:
        return 0.0, 0.0
    probability = coprimeCount / pairsCount
    if probability == 0:
        return probability, 0.0
    piEstimate = (6 / probability) ** 0.5
    return probability, piEstimate
