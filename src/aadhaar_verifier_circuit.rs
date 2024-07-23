
pub use big_uint::*;
use crate::big_uint;
use halo2_base::halo2_proofs::{
    arithmetic::FieldExt, circuit::{Layouter, SimpleFloorPlanner, Value}, plonk::{Circuit, ConstraintSystem, Error}
};
use halo2_base::utils::PrimeField;
use num_bigint::BigUint;
use std::marker::PhantomData;

use crate::timestamp::{TimestampCircuit, TimestampConfig};
use crate::RSASignatureVerifier;
use crate::conditional_secrets::{IdentityCircuit, IdentityConfig};
use crate::signal::{SquareCircuit, SquareConfig};

struct AadhaarQRVerifierCircuit<F: FieldExt, P: PrimeField> {
    //extractor: ExtractAndPackAsIntCircuit,
    hash_and_sign: RSASignatureVerifier<P>,
    cond_secrets: IdentityCircuit,
    timestamp: TimestampCircuit<F>,
    signal: SquareCircuit<F>,
}

impl<F: FieldExt, P:PrimeField> Circuit<F> for AadhaarQRVerifierCircuit<F, P> {
    type Config = (<RSASignatureVerifier<P> as Trait>::Config, 
                    //RSASignatureVerifier<P>::Config,
                    //<conditional_secrets::IdentityCircuit as Trait>::Config, 
                    IdentityConfig,
                    //<timestamp::TimestampCircuit<F> as Trait>::Config, 
                    TimestampConfig,
                    //<signal::SquareCircuit<F> as Trait>::Config,
                    SquareConfig);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        //let extractor = ExtractAndPackAsIntCircuit::configure(cs);
        let hash_and_sign = RSASignatureVerifier::configure(cs);
        let cond_secrets = IdentityCircuit::configure(cs);
        let timestamp = TimestampCircuit::configure(cs);
        let signal = SquareCircuit::configure(cs);

        (hash_and_sign, cond_secrets, timestamp, signal)
    }

    fn synthesize(
        &self,
        cs: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let (hash_and_sign_config, cond_secrets_config, timestamp_config, signal_config) = self.config();

        //self.extractor.synthesize(cs, extractor_config)?;
        self.hash_and_sign.synthesize(cs, hash_and_sign_config)?;
        self.cond_secrets.synthesize(cs, cond_secrets_config)?;
        self.timestamp.synthesize(cs, timestamp_config)?;
        self.signal.synthesize(cs, signal_config)?;

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
        fn run<F: FieldExt, P: PrimeField>() {
            // Extractor Subcircuit
            /*let n_delimited_data = vec![Some(5), Some(10), Some(15), Some(255), Some(1), Some(2)];
            let delimiter_indices = vec![Some(1), Some(2), Some(3)];
            let extractor_circuit = ExtractAndPackAsIntCircuit {
                n_delimited_data: n_delimited_data.iter().map(|&v| Value::known(F::from(v.unwrap()))).collect(),
                delimiter_indices: delimiter_indices.iter().map(|&v| Value::known(F::from(v.unwrap()))).collect(),
                extract_position: 1, // Example value
                extract_max_length: 31, // Example value
                _marker: PhantomData,
            };*/

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
            let hash_and_sign_circuit = RSASignatureVerifier::<F>::new {
                private_key,
                public_key,
                msg: msg.to_vec(),
                _f: PhantomData,
            };
            
            // Conditional Secrets Subcircuit
            let cond_secrets_circuit = IdentityCircuit::new {
                reveal_age_above_18: Some(true),
                age_above_18: Some(1),
                qr_data_age_above_18: Some(1),
                reveal_gender: Some(true),
                gender: Some(1),
                qr_data_gender: Some(1),
                reveal_pincode: Some(true),
                pincode: Some(123456),
                qr_data_pincode: Some(123456),
                reveal_state: Some(true),
                state: Some(1),
                qr_data_state: Some(1),
            };

            // Timestamp Subcircuit
            let timestamp_circuit = TimestampCircuit::new {
                year: Some(Fp::from(2023u64)),
                month: Some(Fp::from(7u64)),
                day: Some(Fp::from(8u64)),
                hour: Some(Fp::from(12u64)),
                minute: Some(Fp::from(34u64)),
                second: Some(Fp::from(56u64)),
            };

            // Signal Hash Subcircuit
            let signal_hash = 5;
            let signal_circuit = SquareCircuit::<F>::new(Value::known(Fp::from(signal_hash)));
            /*{
                Value::known(Fp::from(signal_hash))
            };*/

            // Entire Aadhaar QR Verifier Circuit
            let circuit = AadhaarQRVerifierCircuit {
                //extractor: extractor_circuit,
                hash_and_sign: hash_and_sign_circuit,
                cond_secrets: cond_secrets_circuit,
                timestamp: timestamp_circuit,
                signal: signal_circuit,
            };
    
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
            let prover = match MockProver::run(k, &hash_and_sign_circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            prover.verify().unwrap();

            // Verifying the conditional secrets subcircuit
            let prover: MockProver<Fp> = MockProver::run(k, &cond_secrets_circuit, vec![]).unwrap();
            assert!(prover.verify().is_ok());

            // Verifying the timestamp subcircuit
            let public_inputs = vec![];
            let prover = MockProver::run(k, &timestamp_circuit, public_inputs).unwrap();
            assert_eq!(prover.verify(), Ok(()));

            // Verifying the signal hash subcircuit
            let public_inputs = vec![Fp::from(signal_hash * signal_hash)];
            let prover = MockProver::run(k, &signal_circuit, vec![public_inputs]).unwrap();
            prover.assert_satisfied();

        }
        run::<FieldExt, Fr>();
    }
}
