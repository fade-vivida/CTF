import random
from info import p, q, FLAG

x = random.randint(1, 0xdeadbeef)
y = random.randint(1, 0xc0ffee**2)

print "Many time pads, but enhanced. You can't crack it."
print x * p + FLAG % p
print y * p + FLAG % q
