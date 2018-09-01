import os
import random

secret = [
  171,
  201,
  244,
  200,
  118,
  100,
  138,
  190,
  170,
  159,
  94,
  91,
  42,
  184,
  8,
  98,
  198,
  134,
  110,
  165,
  108,
  219,
  117,
  179,
  180,
  179,
  221,
  144,
  167,
  155
]

for i in range(10000000):
    random.seed(i+1)
    for j in range(len(secret)):
        secret[j] = secret[j] ^ random.randint(0,255)
re = []
for i in range(len(secret)):
    re.append(chr(secret[i]))
print re