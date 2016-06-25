# CacheAttack
1. A demon programm for DES cracking based on cache attack.
2. Can only be used on Linux platform.

# How to use
1. make
2. ./attack demo.R

# Things need to be mentioned 
1. Demo.R is a pre-compiled DES programm. It uses  a 16 kilobyte, 4-way set-associative L1 data cache with 32 byte cache lines.
2. Demo.R uses DES encryption.
3. Demo.R takes a m(plaintext) as the input and return a c(cyphertext) as the output.
4. The program uses cache attack to recover the secret key of Demo.R.
