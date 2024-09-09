
pub use big_uint::*;
use crate::{big_uint, TestRSASignatureWithHashCircuit1, TestRSASignatureWithHashConfig1};
use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner}, plonk::{Circuit, ConstraintSystem, Error}
};
use halo2_base::utils::PrimeField;
use num_bigint::BigUint;

use crate::timestamp::{TimestampCircuit, TimestampConfig};
use crate::conditional_secrets::{IdentityCircuit, IdentityConfig};
use crate::signal::{SquareCircuit, SquareConfig};

#[derive(Clone)]
struct AadhaarQRVerifierCircuit<F: PrimeField> {
    hash_and_sign: TestRSASignatureWithHashCircuit1<F>,
    cond_secrets: IdentityCircuit,
    timestamp: TimestampCircuit<F>,
    signal: SquareCircuit<F>,
}

impl<F: PrimeField> AadhaarQRVerifierCircuit<F> {
    pub fn new(
        hash_and_sign: TestRSASignatureWithHashCircuit1<F>,
        cond_secrets: IdentityCircuit,
        timestamp: TimestampCircuit<F>,
        signal: SquareCircuit<F>,
    ) -> Self {
        Self {
            hash_and_sign,
            cond_secrets,
            timestamp,
            signal,
        }
    }
}

impl<F:PrimeField> Circuit<F> for AadhaarQRVerifierCircuit<F> {
    type Config = (TestRSASignatureWithHashConfig1<F>, 
                    IdentityConfig,
                    TimestampConfig,
                    SquareConfig);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let hash_and_sign = TestRSASignatureWithHashCircuit1::<F>::configure(cs);
        let cond_secrets = IdentityCircuit::configure(cs);
        let timestamp = TimestampCircuit::configure(cs);
        let signal = SquareCircuit::configure(cs);

        (hash_and_sign, cond_secrets, timestamp, signal)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        self.hash_and_sign.synthesize(config.0, layouter)?;
        self.cond_secrets.synthesize(config.1, layouter)?;
        self.timestamp.synthesize(config.2, layouter)?;
        self.signal.synthesize(config.3, layouter)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::big_uint::decompose_biguint;
    use rand::{thread_rng, Rng};
    use rsa::{traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use sha2::{Digest, Sha256};
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::{pasta::Fp, bn256::Fr}};
    use crate::TestRSASignatureWithHashCircuit1;

    #[test]
    fn test_aadhaar_qr_verifier_circuit() {
        fn run<F: PrimeField>() {

            // RSA-SHA256 Subcircuit
            let mut rng = thread_rng();
            let private_key = RsaPrivateKey::new(&mut rng, TestRSASignatureWithHashCircuit1::<F>::BITS_LEN)
                .expect("failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
            let n = BigUint::from_radix_le(&public_key.n().to_radix_le(16), 16).unwrap();
            let mut msg: [u8; 128] = [0; 128];
            for i in 0..128 {
                msg[i] = rng.gen();
            }
            let hashed_msg = Sha256::digest(&msg);
            let hash_and_sign_circuit = TestRSASignatureWithHashCircuit1::<F>::new(
                private_key,
                public_key,
                msg.to_vec(),
                //_f: PhantomData,
            );
            
            // Conditional Secrets Subcircuit
            let cond_secrets_circuit = IdentityCircuit::new(
                Some(true),
                Some(1),
                Some(1),
                Some(true),
                Some(1),
                Some(1),
                Some(true),
                Some(123456),
                Some(123456),
                Some(true),
                Some(1),
                Some(1));

            // Timestamp Subcircuit
            let timestamp_circuit = TimestampCircuit::<F>::new(Some(F::from(2023u64)),
                Some(F::from(7u64)),
                Some(F::from(8u64)),
                Some(F::from(12u64)),
                Some(F::from(34u64)),
                Some(F::from(56u64)));

            // Signal Hash Subcircuit
            let signal_hash = 5;
            let signal_circuit = SquareCircuit::<F>::new(F::from(signal_hash));

            // Entire Aadhaar QR Verifier Circuit
            let _circuit = AadhaarQRVerifierCircuit::<F>::new(
                hash_and_sign_circuit.clone(),
                cond_secrets_circuit.clone(),
                timestamp_circuit.clone(),
                signal_circuit.clone(),
            );
    
            // Verifying the RSA-SHA256 subcircuit
            let num_limbs = 2048 / 64;
            let limb_bits = 64;
            let n_fes = decompose_biguint::<F>(&n, num_limbs, limb_bits);
            let hash_fes = hashed_msg
                .iter()
                .map(|byte| F::from(*byte as u64))
                .collect::<Vec<F>>();
            let public_inputs = vec![n_fes, hash_fes];
            let k = 15;
            let prover = match MockProver::run(k, &hash_and_sign_circuit.clone(), public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify().unwrap();

            // Verifying the conditional secrets subcircuit
            let prover: MockProver<Fp> = MockProver::run(k, &cond_secrets_circuit.clone(), vec![]).unwrap();
            assert!(prover.verify().is_ok());

            // Verifying the timestamp subcircuit
            let public_inputs = vec![];
            let prover = MockProver::run(k, &timestamp_circuit.clone(), public_inputs).unwrap();
            assert_eq!(prover.verify(), Ok(()));

            // Verifying the signal hash subcircuit
            let public_inputs = vec![F::from(signal_hash * signal_hash)];
            let prover = MockProver::run(k, &signal_circuit.clone(), vec![public_inputs]).unwrap();
            prover.assert_satisfied();

        }
        run::<Fr>();
    }
}
