use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner}, halo2curves::pasta::pallas, 
    plonk::{Advice, Circuit, Column, ConstraintSystem, Instance, Selector, Error}
};

//use halo2_ecc::halo2_base::poseidon;
use poseidon::Poseidon;

#[derive(Default, Clone)]
struct PoseidonCircuit {
    nullifier_seed: u64,          // Nullifier seed as u64
    photo: Vec<u64>,              // Photo as a vector of u64
}

#[derive(Default, Clone)]
struct PoseidonConfig {
    poseidon_selector: Selector,
    advice: Column<Advice>,
    instance: Column<Instance>,
}

impl Circuit<pallas::Scalar> for PoseidonCircuit {
    type Config = PoseidonConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn configure(meta: &mut ConstraintSystem<pallas::Scalar>) -> Self::Config {
        let poseidon_selector = meta.selector();
        let advice = meta.advice_column();
        let instance = meta.instance_column();

        meta.create_gate("Poseidon Hash", |v| {
            // Example constraint for Poseidon hash
            let s = poseidon_selector;
            vec![s.clone() * (v[0] - v[1])] // Placeholder for actual constraints
        });

        PoseidonConfig {
            poseidon_selector,
            advice,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Scalar>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Poseidon Hash",
            |mut region| {
                let mut poseidon = Poseidon::new();

                // Assign nullifier seed
                let nullifier_seed = self.nullifier_seed;

                // Compute the Poseidon hash
                let hash = poseidon.hash(&[nullifier_seed], &self.photo);

                // Assign the hash output to the circuit
                region.assign_advice(
                    || "hash output",
                    config.advice,
                    0,
                    || Ok(hash.into()),
                )?;

                Ok(())
            },
        )
    }
    
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }
}

// Test function for the circuit
#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::dev::MockProver;

    #[test]
    fn test_poseidon_circuit() {
        let nullifier_seed = 12345678u64; // Example nullifier seed
        let photo = vec![1u64, 2, 3, 4];     // Example photo data

        let circuit = PoseidonCircuit {
            nullifier_seed,
            photo,
        };

        // Create a mock prover with the circuit
        let k = 4; // Number of rows in the circuit
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();

        // Verify the proof
        assert!(prover.verify().is_ok());

        // Get the computed hash from the instance column
        let hash = prover.instance(0, 0).unwrap();
        println!("Computed hash: {:?}", hash);
    }
}

/*use halo2_base::halo2_proofs::{
    arithmetic::FieldExt, circuit::{Layouter, SimpleFloorPlanner}, 
    halo2curves::pasta::Fp, 
    plonk::{Advice, Circuit, ConstraintSystem, Error, Instance, Column},
};

use crate::halo2_ecc::halo2_base::{
    poseidon::{
        hasher::{PoseidonChip, PoseidonInstructions, range_chip},
        spec::OptimizedPoseidonSpec,
    },
    safe_types::FixLenBytes,
    gates:: RangeChip,
};

const PHOTO_SIZE: usize = 32;
#[derive(Default)]
struct NullifierCircuit {
    nullifier_seed: Option<Fp>,
    photo: [Option<Fp>; PHOTO_SIZE],
    out: Option<Fp>,
}
#[derive(Clone)]
pub struct NullifierConfig {
    pub nullifier_seed: Column<Advice>,
    pub photo: [Column<Advice>; PHOTO_SIZE],
    pub out: Column<Instance>,
}

impl<F: FieldExt> Circuit<F> for NullifierCircuit {
    //type Config = NullifierConfig;
    type Config = PoseidonChip<F, 3, 2>;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self {
            nullifier_seed: None,
            photo: [None; PHOTO_SIZE],
            out: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let range_chip = RangeChip::default();
        let poseidon_spec = OptimizedPoseidonSpec::new::<3, 2, 3>(); // Example Poseidon spec, adjust as needed
        PoseidonChip::<F, 3, 2>::new(meta, poseidon_spec, &range_chip)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Nullifier calculation",
            |mut region| {
                let poseidon_spec = OptimizedPoseidonSpec::new::<3, 2, 3>();
                let poseidon_chip = PoseidonChip::<F, 3, 2>::new(config, poseidon_spec);
                let mut hasher = PoseidonInstructions::new(poseidon_chip);

                let first16_hash = hasher.hash_fix_len_bytes(config, &FixLenBytes::new(&self.photo[0..16]))?;
                let last16_hash = hasher.hash_fix_len_bytes(config, &FixLenBytes::new(&self.photo[16..32]))?;

                let out = poseidon_chip.hash_fix_len_bytes(config, &FixLenBytes::new(&[self.nullifier_seed, first16_hash, last16_hash]))?;
                
                // Output the final hash
                region.assign_advice(
                    || "output",
                    config.output,
                    0,
                    || out,
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn nullifier_test() {
        let circuit = NullifierCircuit {
            nullifier_seed: Some(Fp::from(12345)), // Replace with actual nullifier seed
            photo: [Some(Fp::from(1)); PHOTO_SIZE], // Example initialization, replace with actual photo data
            out: None,
        };

        let public_inputs = vec![];
    
        let prover = MockProver::<Fp>::run(10, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

    /*fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Poseidon template supports only 16 inputs - so we do in two chunks (photo is 32 chunks)
        let first_16_hash = {
            let mut sponge = PoseidonSponge::<PrimeField>::new(config.clone());
            for i in 0..16 {
                sponge.absorb(layouter.namespace(|| format!("absorb_first_{}", i)), self.photo[i])?;
            }
            sponge.squeeze(layouter.namespace(|| "squeeze_first"))
        }?;

        let last_16_hash = {
            let mut sponge = PoseidonSponge::<PrimeField>::new(config.clone());
            for i in 0..16 {
                sponge.absorb(layouter.namespace(|| format!("absorb_last_{}", i)), self.photo[i + 16])?;
            }
            sponge.squeeze(layouter.namespace(|| "squeeze_last"))
        }?;

        let nullifier = {
            let mut sponge = PoseidonSponge::<PrimeField>::new(config.clone());
            sponge.absorb(layouter.namespace(|| "absorb_seed"), self.nullifier_seed)?;
            sponge.absorb(layouter.namespace(|| "absorb_first_16_hash"), first_16_hash)?;
            sponge.absorb(layouter.namespace(|| "absorb_last_16_hash"), last_16_hash)?;
            sponge.squeeze(layouter.namespace(|| "squeeze_nullifier"))
        }?;

        layouter.constrain_instance(nullifier.cell(), 0)?;

        Ok(())
    }
}

fn main() {
    // Instantiate the circuit with the desired parameters and values.
    let circuit = NullifierCircuit {
        nullifier_seed: Value::known(PrimeField::from(/* your nullifier seed here */)),
        photo: vec![/* your photo data here */],
    };

    // Create a prover and verify the circuit.
    // Here you can use the actual proving and verification code.
}*/*/ 
