import string
import random

alphabet = list(string.uppercase + string.digits)
alphabet.remove('I') # not easy to distinguish visually
alphabet.remove('1')
alphabet.remove('0')
alphabet.remove('O')
alphabet = "".join(alphabet)

_gen = random.Random()
with open('/dev/urandom', 'rb') as f:
    _gen.seed(f.read(12))


def newTicket():
    t = "".join(_gen.choice(alphabet) for i in range(16))
    return "%s-%s-%s-%s" % (t[:4], t[4:8], t[8:12], t[12:16])


