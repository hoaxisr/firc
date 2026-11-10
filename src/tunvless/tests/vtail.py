import sys
c = open(sys.argv[1], "rb").read()
o = open(sys.argv[2], "rb").read()
s = int(sys.argv[3])
neg = "--not" in sys.argv[4:]
t = o[s:]
hit = c.endswith(t)
print("client %d B, origin %d B, S %d, origin tail %d B, client ends with it: %s" % (len(c), len(o), s, len(t), "yes" if hit else "no"))
sys.exit(0 if len(t) >= 1 and hit != neg else 1)
