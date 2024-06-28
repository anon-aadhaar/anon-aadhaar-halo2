
use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value}, 
    plonk::{Circuit, ConstraintSystem, Error}
};
use halo2_gadgets::poseidon::{PoseidonChip, PoseidonConfig, primitives::P128Pow5T3, PaddedWord};
use halo2_base::utils::PrimeField;
use halo2_gadgets::poseidon::primitives::Absorbing;

#[derive(Default)]
struct NullifierCircuit<F: PrimeField> {
    nullifier_seed: Value<F>,
    photo: Vec<Value<F>>, // 32 elements
}

impl<F: PrimeField> Circuit<F> for NullifierCircuit<F> {
    type Config = PoseidonConfig<PrimeField>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> NullifierCircuit<F> {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        PoseidonConfig::<PrimeField>::configure(meta, P128Pow5T3)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Define the Poseidon chip and state
        let chip = PoseidonChip::<F>::new(config.clone());
        let mut state_first = chip.initialize_state();
        let mut state_last = chip.initialize_state();
        let mut state_nullifier = chip.initialize_state();

        // First 16 hash
        let first_16_hash = {
            let input: Vec<_> = (0..16).map(|i| self.photo[i].into()).collect();
            let absorbing = Absorbing::<PaddedWord<PrimeField>, RATE>::from(input);
            poseidon_sponge(&chip, &mut layouter, &mut state_first, Some(&absorbing))?
        };

        // Last 16 hash
        let last_16_hash = {
            let input: Vec<_> = (0..16).map(|i| self.photo[i + 16].into()).collect();
            let absorbing = Absorbing::<PaddedWord<F>, RATE>::from(input);
            poseidon_sponge(&chip, &mut layouter, &mut state_last, Some(&absorbing))?
        };

        // Nullifier
        let nullifier = {
            let mut absorbing = Vec::new();
            absorbing.push(self.nullifier_seed.into());
            absorbing.push(first_16_hash.into());
            absorbing.push(last_16_hash.into());
            let absorbing = Absorbing::<PaddedWord<F>, RATE>::from(absorbing);
            poseidon_sponge(&chip, &mut layouter, &mut state_nullifier, Some(&absorbing))?
        };
        
        // Constrain the output
        layouter.constrain_instance(nullifier.cell(), config.hash_instance ,0)?;

        Ok(())
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
    }*/
}
/* 
fn main() {
    // Instantiate the circuit with the desired parameters and values.
    let circuit = NullifierCircuit {
        nullifier_seed: Value::known(PrimeField::from(/* your nullifier seed here */)),
        photo: vec![/* your photo data here */],
    };

    // Create a prover and verify the circuit.
    // Here you can use the actual proving and verification code.
}
*/