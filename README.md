This repo contains the Halo2 implementation for the Anon-Aadhaar protocol.

The main components of the circuit are :-
1. Verification of an RSA signature of a SHA-256 hashed message.
2. Extraction of fields from signed data. If reveal true: age > 18, gender, state, pincode.
3. Computing the Nullifier from the Poseidon Hash function.
4. Conversion of IST timestamp to UTC UNIX timestamp.
5. Apply constraints on the signal hash. 

How to build and run the repo:
1. cargo update -p half@2.4.1 --precise 2.2.0
2. cargo build
3. cargo test 

Benchmarks:

| Part of the Circuit | Proving Time | Verification Time |
|-----------------|-----------------|-----------------|
| RSA-SHA256    | 14.442124258s    | 11.461932341s    |
| Nullifier    | 322.659513ms    | 96.948µs    |
| Conditional Secrets    | 17.916018ms    | 307.496281ms    |
| Timestamp    | 9.821774ms    | 1.990614ms    |
| Signal    | 12.089368ms    | 78.350583ms    |