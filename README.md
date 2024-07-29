This repo contains the Halo2 implementation for the Anon-Aadhaar protocol.
At this point, the main components are :-
1. Verification of an RSA signature of a SHA-256 hashed message.
2. Extraction of fields from signed data. If reveal true: age > 18, gender, state, pincode.
3. Computing the Nullifier from the Poseidon Hash function.
4. Conversion of IST timestamp to UTC UNIX timestamp.
5. Apply constraints on the signal hash. 

How to build and run the repo:
1. cargo update -p half@2.4.1 --precise 2.2.0
2. cargo build
3. cargo test
