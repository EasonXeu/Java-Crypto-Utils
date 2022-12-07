Referring to this
documentation [Elliptic Curve Integrated Encryption Scheme - Crypto++ Wiki](https://www.cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme)
.

Basically, there are two kinds of key suites with ECIES. One is the IEEE P1363's version of ECIES, while the other is
Shoup's version of ECIES. IEEE's version of ECIES was a slightly different algorithm than Shoup recommended.

Crypto++ originally implemented IEEE P1363's version of ECIES. Botan and Bouncy Castle implemented Shoup's version of
ECIES, so Crypto++ Botan and Bouncy Castle did not interop. But the non-interop was fixed at Crypto++ 6.0.

In the current package ecies, we have three kinds of implementations.

For the basic package, it is the simplest implementation, just for test, it is not recommended
For the common package, it is the most useful implementation, recommended.
For the custom package, it is for the case where we have to write the ECIES framework by ourselves.