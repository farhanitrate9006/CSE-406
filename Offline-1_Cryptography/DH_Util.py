# Python3 program Miller-Rabin primality test
import random

# Utility function to do
# modular exponentiation.
# It returns (x^y) % p
def modularExp(x, y, p):
	if (y == 0):
		return 1;
	elif (y % 2 == 0):
		return modularExp((x * x) % p, y // 2, p)
	return (x * modularExp((x * x) % p, (y - 1) // 2, p)) % p

# This function is called
# for all k trials. It returns
# false if n is composite and
# returns false if n is
# probably prime. d is an odd
# number such that d*2<sup>r</sup> = n-1
# for some r >= 1
def miillerTest(d, n):
	
	# Pick a random number in [2..n-2]
	# Corner cases make sure that n > 4
	a = 2 + random.randint(1, n - 4);

	# Compute a^d % n
	x = modularExp(a, d, n);

	if (x == 1 or x == n - 1):
		return True;

	# Keep squaring x while one
	# of the following doesn't
	# happen
	# (i) d does not reach n-1
	# (ii) (x^2) % n is not 1
	# (iii) (x^2) % n is not n-1
	while (d != n - 1):
		x = (x * x) % n;
		d *= 2;

		if (x == 1):
			return False;
		if (x == n - 1):
			return True;

	# Return composite
	return False;

# It returns false if n is
# composite and returns true if n
# is probably prime. k is an
# input parameter that determines
# accuracy level. Higher value of
# k indicates more accuracy.
def isPrime(n, k):
	
	# Corner cases
	if (n <= 1 or n == 4):
		return False;
	if (n <= 3):
		return True;

	# Find r such that n =
	# 2^d * r + 1 for some r >= 1
	d = n - 1;
	while (d % 2 == 0):
		d //= 2;

	# Iterate given number of 'k' times
	for i in range(k):
		if (miillerTest(d, n) == False):
			return False;

	return True;
