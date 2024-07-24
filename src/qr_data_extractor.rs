use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Column, Instance, Advice},
    //poly::Rotation,
};

use halo2_base::utils::PrimeField;

#[derive(Clone)]
struct AadhaarQRVerifierConfig {
    qr_data_padded: Column<Advice>,
    qr_data_padded_length: Column<Advice>,
    delimiter_indices: Column<Advice>,
    signature: Column<Advice>,
    pub_key: Column<Advice>,
    reveal_age_above18: Column<Advice>,
    reveal_gender: Column<Advice>,
    reveal_pin_code: Column<Advice>,
    reveal_state: Column<Advice>,
    nullifier_seed: Column<Instance>,
    signal_hash: Column<Instance>,
    pubkey_hash: Column<Instance>,
    nullifier: Column<Instance>,
    timestamp: Column<Instance>,
    age_above18: Column<Instance>,
    gender: Column<Instance>,
    pin_code: Column<Instance>,
    state: Column<Instance>,
}

#[derive(Clone)]
pub struct AadhaarQRVerifierCircuit<F: PrimeField> {
    qr_data_padded: Vec<Option<F>>,
    qr_data_padded_length: Option<F>,
    delimiter_indices: Vec<Option<F>>,
    signature: Vec<Option<F>>,
    pub_key: Vec<Option<F>>,
    reveal_age_above18: Option<F>,
    reveal_gender: Option<F>,
    reveal_pin_code: Option<F>,
    reveal_state: Option<F>,
    nullifier_seed: Option<F>,
    signal_hash: Option<F>,
}

impl <F: PrimeField> Circuit<F> for  AadhaarQRVerifierCircuit<F> {
    type Config = AadhaarQRVerifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let qr_data_padded = meta.advice_column();
        let qr_data_padded_length = meta.advice_column();
        let delimiter_indices = meta.advice_column();
        let signature = meta.advice_column();
        let pub_key = meta.advice_column();
        let reveal_age_above18 = meta.advice_column();
        let reveal_gender = meta.advice_column();
        let reveal_pin_code = meta.advice_column();
        let reveal_state = meta.advice_column();

        let nullifier_seed = meta.instance_column();
        let signal_hash = meta.instance_column();
        let pubkey_hash = meta.instance_column();
        let nullifier = meta.instance_column();
        let timestamp = meta.instance_column();
        let age_above18 = meta.instance_column();
        let gender = meta.instance_column();
        let pin_code = meta.instance_column();
        let state = meta.instance_column();

        AadhaarQRVerifierConfig {
            qr_data_padded,
            qr_data_padded_length,
            delimiter_indices,
            signature,
            pub_key,
            reveal_age_above18,
            reveal_gender,
            reveal_pin_code,
            reveal_state,
            nullifier_seed,
            signal_hash,
            pubkey_hash,
            nullifier,
            timestamp,
            age_above18,
            gender,
            pin_code,
            state,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign inputs",
            |mut region| {
                for (i, &value) in self.qr_data_padded.iter().enumerate() {
                    region.assign_advice(
                        || format!("qr_data_padded {}", i),
                        config.qr_data_padded,
                        i,
                        || Value::known(value.unwrap_or(F::from(1)))
                    )?;
                }

                region.assign_advice(
                    || "qr_data_padded_length",
                    config.qr_data_padded_length,
                    0,
                    || Value::known(self.qr_data_padded_length.unwrap_or(F::from(1)))
                )?;

                for (i, &value) in self.delimiter_indices.iter().enumerate() {
                    region.assign_advice(
                        || format!("delimiter_indices {}", i),
                        config.delimiter_indices,
                        i,
                        || Value::known(value.unwrap_or(F::from(1)))
                    )?;
                }

                for (i, &value) in self.signature.iter().enumerate() {
                    region.assign_advice(
                        || format!("signature {}", i),
                        config.signature,
                        i,
                        || Value::known(value.unwrap_or(F::from(1)))
                    )?;
                }

                for (i, &value) in self.pub_key.iter().enumerate() {
                    region.assign_advice(
                        || format!("pub_key {}", i),
                        config.pub_key,
                        i,
                        || Value::known(value.unwrap_or(F::from(1)))
                    )?;
                }

                region.assign_advice(
                    || "reveal_age_above18",
                    config.reveal_age_above18,
                    0,
                    || Value::known(self.reveal_age_above18.unwrap_or(F::from(1)))
                )?;

                region.assign_advice(
                    || "reveal_gender",
                    config.reveal_gender,
                    0,
                    || Value::known(self.reveal_gender.unwrap_or(F::from(1)))
                )?;

                region.assign_advice(
                    || "reveal_pin_code",
                    config.reveal_pin_code,
                    0,
                    || Value::known(self.reveal_pin_code.unwrap_or(F::from(1)))
                )?;

                region.assign_advice(
                    || "reveal_state",
                    config.reveal_state,
                    0,
                    || Value::known(self.reveal_state.unwrap_or(F::from(1)))
                )?;

                region.assign_advice_from_instance(
                    || "nullifier_seed", 
                    config.nullifier_seed, 
                    0, 
                    || Value::known(self.nullifier_seed.unwrap_or(F::from(1))), 
                    0);
                // Assign public inputs
                /*region.assign_instance_(
                    || "nullifier_seed",
                    config.nullifier_seed,
                    0,
                    //|| Value::known(self.nullifier_seed.ok_or(Error::Synthesis)?),
                    || Value::known(self.nullifier_seed.unwrap_or(F::from(1)))
                )?;*/
                
                region.assign_instance(
                    || "signal_hash",
                    config.signal_hash,
                    0,
                    //|| Value::known(self.signal_hash.ok_or(Error::Synthesis)?),
                    || Value::known(self.signal_hash.unwrap_or(F::from(1)))
                )?;

                Ok(())
            },
        )?;

        // Additional logic to compute the outputs: pubkeyHash, nullifier, timestamp, ageAbove18, gender, pinCode, state
        // This requires implementing the cryptographic primitives and calculations involved.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::dev::MockProver;
    use halo2_base::halo2_proofs::halo2curves::bn256::Fr as Fp;
    use std::vec;

    #[test]
    fn test_aadhaar_qr_verifier() {
        let k = 5;
        let circuit = AadhaarQRVerifierCircuit::<Fp> {
            qr_data_padded: vec![Some(Fp::from(1)), Some(Fp::from(2)), Some(Fp::from(3))],
            qr_data_padded_length: Some(Fp::from(3)),
            delimiter_indices: vec![Some(Fp::from(1)), Some(Fp::from(2)), Some(Fp::from(3)), Some(Fp::from(4))],
            signature: vec![Some(Fp::from(1)), Some(Fp::from(2))],
            pub_key: vec![Some(Fp::from(1)), Some(Fp::from(2))],
            reveal_age_above18: Some(Fp::from(1)),
            reveal_gender: Some(Fp::from(1)),
            reveal_pin_code: Some(Fp::from(1)),
            reveal_state: Some(Fp::from(1)),
            nullifier_seed: Some(Fp::from(1)),
            signal_hash: Some(Fp::from(1)),
        };

        // Public inputs
        let public_inputs = vec![
            vec![
                Fp::from(1), // nullifier_seed
                Fp::from(1), // signal_hash
            ]
        ];

        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        prover.assert_satisfied();
    }
}
