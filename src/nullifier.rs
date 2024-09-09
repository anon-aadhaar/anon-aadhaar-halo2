use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner}, halo2curves::pasta::pallas, 
    plonk::{Advice, Circuit, Column, ConstraintSystem, Instance, Selector, Error}
};

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
