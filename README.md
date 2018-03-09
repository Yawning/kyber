### Kyber - IND-CCA2-secure Key Encapsulation Mechanism
#### Yawning Angel (yawning at schwanenlied dot me)

[![GoDoc](https://godoc.org/git.schwanenlied.me/yawning/kyber.git?status.svg)](https://godoc.org/git.schwanenlied.me/yawning/kyber.git)

This package implements the Kyber IND-CCA2-secure key encapsulation
mechanism (KEM), based on the hardness of solving the learning-with-errors
(LWE) problem over module lattices as submitted to the NIST Post-Quantum
Cryptography project.

This implementation is a port of the Public Domain reference implementation
by Joppe Bos, Léo Ducas, Eike Kiltz , Tancrède Lepoint, Vadim Lyubashevsky,
John Schanck, Peter Schwabe, Gregor Seiler, and Damien Stehlé.

Additionally implementations of Kyber.AKE and Kyber.UAKE as presented in
the Kyber paper are included for users that seek an authenticated key
exchange.

Note that the algorithm is not finalized yet, and may change in a backward
incompatible manner in the future.  The designers currently recommend
combining Kyber with an established pre-quantum algorithm like ECDH, and
using the Kyber-768 parameter set.

For more information, see the [project home page](https://pq-crystals.org/kyber/index.shtml).
