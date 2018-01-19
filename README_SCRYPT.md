The scrypt key derivation function
----------------------------------


The scrypt key derivation function was originally developed for use in the
[Tarsnap online backup system](http://www.tarsnap.com/index.html) and is
designed to be far more secure against hardware brute-force attacks than
alternative functions such as [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) or
[bcrypt](http://www.openbsd.org/papers/bcrypt-paper.ps).

We estimate that on modern (2009) hardware, if 5 seconds are spent computing a
derived key, the cost of a hardware brute-force attack against `scrypt` is
roughly 4000 times greater than the cost of a similar attack against bcrypt (to
find the same password), and 20000 times greater than a similar attack against
PBKDF2.

Details of the `scrypt` key derivation function are given in a paper which was
presented at the [BSDCan'09](http://www.bsdcan.org/2009/) conference:

* Colin Percival, [Stronger Key Derivation via Sequential Memory-Hard
  Functions](http://www.tarsnap.com/scrypt/scrypt.pdf), presented at BSDCan'09,
  May 2009.
* Conference presentation slides:
  [PDF](http://www.tarsnap.com/scrypt/scrypt-slides.pdf).

More details are given in the Internet Engineering Task Force
(IETF)
[RFC 7914: The scrypt Password-Based Key Derivation Function](https://tools.ietf.org/html/rfc7914).

It has been demonstrated that scrypt is maximally memory-hard:

* J. Alwen, B. Chen, K. Pietrzak, L. Reyzin, S. Tessaro,
  [Scrypt is Maximally Memory-Hard](http://eprint.iacr.org/2016/989),
  Cryptology ePrint Archive: Report 2016/989.

Testing
-------

A small test suite can be run with:

    make test

Memory-testing normal operations with valgrind (takes approximately 4 times as
long as no valgrind tests) can be enabled with:

    make test USE_VALGRIND=1

Memory-testing all tests with valgrind (requires over 1 GB memory, and takes
approximately 4 times as long as `USE_VALGRIND=1`) can be enabled with:

    make test USE_VALGRIND=2


Mailing list
------------

The scrypt key derivation function and the scrypt encryption utility are
discussed on the <scrypt@tarsnap.com> mailing list.
