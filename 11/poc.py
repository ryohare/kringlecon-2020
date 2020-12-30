import random
from mt19937predictor import MT19937Predictor

predictor = MT19937Predictor()

for _ in range(624):
	x = random.randrange(0xFFFFFFFFFFFFFFFF)
	predictor.setrandbits(x,64)

print(predictor.getrandbits(64) == random.randrange(0xFFFFFFFFFFFFFFFF))
