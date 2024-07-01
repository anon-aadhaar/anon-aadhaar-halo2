use crate::{
    gates::{RangeChip, RangeInstructions},
    poseidon::hasher::{OptimizedPoseidonSpec, PoseidonHasher},
    safe_types::{VarLenBytes, VarLenBytesVec},
    utils::{BigPrimeField, ScalarField},
    AssignedValue, Context,
};
use itertools::Itertools;

// Assuming the following imports are available in your context setup
// pub mod poseidon::hasher;

pub struct PoseidonChip<'a, F: ScalarField, const T: usize, const RATE: usize> {
    range_chip: &'a RangeChip<F>,
    hasher: PoseidonHasher<F, T, RATE>,
}

impl<'a, F: ScalarField, const T: usize, const RATE: usize> PoseidonChip<'a, F, T, RATE> {
    pub fn new(ctx: &mut Context<F>, spec: OptimizedPoseidonSpec<F, T, RATE>, range_chip: &'a RangeChip<F>) -> Self {
        let mut hasher = PoseidonHasher::new(spec);
        hasher.initialize_consts(ctx, range_chip.gate());
        Self { range_chip, hasher }
    }
}

impl<'a, F: ScalarField, const T: usize, const RATE: usize> PoseidonInstructions<F> for PoseidonChip<'a, F, T, RATE> {
    fn hash_var_len_bytes_vec(&self, ctx: &mut Context<F>, inputs: &VarLenBytesVec<F>) -> AssignedValue<F> {
        let inputs_len = inputs.len();
        self.hasher.hash_var_len_array(
            ctx,
            self.range_chip,
            &inputs.bytes().iter().map(|sb| *sb.as_ref()).collect_vec(),
            *inputs_len,
        )
    }
}

pub struct Nullifier<F: ScalarField> {
    nullifier_seed: AssignedValue<F>,
    photo: Vec<AssignedValue<F>>, // Assuming AssignedValue<F> represents the input values
}

impl<F: ScalarField> Nullifier<F> {
    pub fn new(nullifier_seed: AssignedValue<F>, photo: Vec<AssignedValue<F>>) -> Self {
        Self {
            nullifier_seed,
            photo,
        }
    }

    pub fn calculate_nullifier(&self, ctx: &mut Context<F>) -> Result<AssignedValue<F>, Error> {
        // Poseidon hasher specification
        let spec = OptimizedPoseidonSpec::<F, 3, RATE>::default();
        let range_chip = RangeChip::new(ctx, spec.rate());

        // First 16 elements hashing
        let mut first16_hasher = PoseidonChip::new(ctx, spec.clone(), &range_chip);
        let first16_inputs: Vec<_> = self.photo[..16].to_vec();
        let first16_hash = first16_hasher.hash_var_len_bytes_vec(ctx, &VarLenBytesVec::from(&first16_inputs))?;

        // Last 16 elements hashing
        let mut last16_hasher = PoseidonChip::new(ctx, spec.clone(), &range_chip);
        let last16_inputs: Vec<_> = self.photo[16..].to_vec();
        let last16_hash = last16_hasher.hash_var_len_bytes_vec(ctx, &VarLenBytesVec::from(&last16_inputs))?;

        // Final Poseidon hash calculation
        let nullifier_hash = PoseidonChip::new(ctx, spec, &range_chip)
            .hash_var_len_bytes_vec(ctx, &VarLenBytesVec::from(&[self.nullifier_seed, first16_hash, last16_hash]))?;

        Ok(nullifier_hash)
    }
}

#[cfg(test)]
mod test {
    // Import necessary crates and modules
    use halo2::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, ConstraintSystem, Error},
        poly::Rotation,
    };
    use halo2_ecc::fields::{FpChip, RangeChip};
    use halo2_poseidon::{OptimizedPoseidonSpec, PoseidonChip};

    // Import your Nullifier struct and other necessary items
    use crate::Nullifier; 

    // Define a test function
    #[test]
    fn test_nullifier_calculation() {
        // Initialize a Halo2 context (MockProver for testing purposes)
        let mut prover = MockProver::<Fp>::new();

        // Setup components (RangeChip and Poseidon hasher)
        let spec = OptimizedPoseidonSpec::<Fp, 3, RATE>::default();
        let range_chip = RangeChip::new(&mut prover.context(), spec.rate());
        let poseidon_chip = PoseidonChip::new(&mut prover.context(), spec.clone(), &range_chip);

        // Test inputs (example values, adjust as per your actual inputs)
        let nullifier_seed = AssignedValue::new(Fp::from(12345)); // Example nullifier seed
        let photo = vec![
            AssignedValue::new(Fp::from(1)),  // Example photo values (adjust as needed)
            AssignedValue::new(Fp::from(2)),
            // Add more values as needed up to 32 elements
        ];

        // Create a Nullifier instance with test inputs
        let nullifier = Nullifier::new(nullifier_seed, photo.clone());

        // Calculate the nullifier hash
        let result = nullifier.calculate_nullifier(&mut prover.context());
        assert!(result.is_ok(), "Nullifier calculation failed: {:?}", result.err());

        // Optionally, verify the nullifier hash against expected values
        let expected_hash = result.unwrap();
        let expected_value = Fp::from(123456789); // Example expected nullifier hash value
        assert_eq!(expected_hash.value(), &expected_value);
    }
}