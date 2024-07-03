use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{circuit::*, plonk::*};
use halo2curves::pasta::Fp as PastaFp;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    inputs: Vec<Column<Advice>>,
    instance: Column<Instance>,
    pow5_config: Pow5Config<PastaFp, WIDTH, RATE>,
}

#[derive(Debug, Clone)]
pub struct PoseidonChip<S: Spec<PastaFp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> {
    config: PoseidonConfig<WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<S: Spec<PastaFp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> PoseidonChip<S, WIDTH, RATE, L> {
    pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<PastaFp>) -> PoseidonConfig<WIDTH, RATE, L> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let instance = meta.instance_column();
        for i in 0..WIDTH {
            meta.enable_equality(state[i]);
        }
        meta.enable_equality(instance);
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox.try_into().unwrap(),
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig {
            inputs: state.clone().try_into().unwrap(),
            instance,
            pow5_config: pow5_config,
        }
    }

    pub fn load_private_inputs(
        &self,
        mut layouter: impl Layouter<PastaFp>,
        inputs: [Value<PastaFp>; L],
    ) -> Result<[AssignedCell<PastaFp, PastaFp>; L], Error> {
        layouter.assign_region(
            || "load private inputs",
            |mut region| -> Result<[AssignedCell<PastaFp, PastaFp>; L], Error> {
                let result = inputs
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || "private input",
                            self.config.inputs[i],
                            0,
                            || x.to_owned(),
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<PastaFp, PastaFp>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<PastaFp>,
        cell: &AssignedCell<PastaFp, PastaFp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<PastaFp>,
        words: &[AssignedCell<PastaFp, PastaFp>; L],
    ) -> Result<AssignedCell<PastaFp, PastaFp>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());
        let word_cells = layouter.assign_region(
            || "load words",
            |mut region| -> Result<[AssignedCell<PastaFp, PastaFp>; L], Error> {
                let result = words
                    .iter()
                    .enumerate()
                    .map(|(i, word)| {
                        word.copy_advice(
                            || format!("word {}", i),
                            &mut region,
                            self.config.inputs[i],
                            0,
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<PastaFp, PastaFp>>, Error>>();
                Ok(result?.try_into().unwrap())
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), word_cells)
    }
}

#[derive(Debug, Clone)]
pub struct NullifierConfig {
    photo_inputs: Vec<Column<Advice>>,
    nullifier_seed: Column<Advice>,
    output: Column<Advice>,
    poseidon_config_16: PoseidonConfig<16, 8, 16>,
    poseidon_config_3: PoseidonConfig<3, 3, 3>,
}

#[derive(Debug, Clone)]
pub struct NullifierChip {
    config: NullifierConfig,
}

impl NullifierChip {
    pub fn construct(config: NullifierConfig) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<PastaFp>) -> NullifierConfig {
        let photo_inputs = (0..32).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let nullifier_seed = meta.advice_column();
        let output = meta.advice_column();
        
        let poseidon_config_16 = PoseidonChip::<_, 16, 8, 16>::configure(meta);
        let poseidon_config_3 = PoseidonChip::<_, 3, 3, 3>::configure(meta);
        
        NullifierConfig {
            photo_inputs,
            nullifier_seed,
            output,
            poseidon_config_16,
            poseidon_config_3,
        }
    }

    pub fn load_private_inputs(
        &self,
        mut layouter: impl Layouter<PastaFp>,
        nullifier_seed: Value<PastaFp>,
        photo: [Value<PastaFp>; 32],
    ) -> Result<(AssignedCell<PastaFp, PastaFp>, Vec<AssignedCell<PastaFp, PastaFp>>), Error> {
        let nullifier_seed_cell = layouter.assign_region(
            || "load nullifier seed",
            |mut region| {
                region.assign_advice(
                    || "nullifier seed",
                    self.config.nullifier_seed,
                    0,
                    || nullifier_seed.clone(),
                )
            },
        )?;

        let photo_cells = layouter.assign_region(
            || "load photo inputs",
            |mut region| {
                photo.iter().enumerate().map(|(i, &photo)| {
                    region.assign_advice(
                        || format!("photo input {}", i),
                        self.config.photo_inputs[i],
                        0,
                        || photo.clone(),
                    )
                }).collect::<Result<Vec<_>, _>>()
            },
        )?;
        
        Ok((nullifier_seed_cell, photo_cells))
    }

    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<PastaFp>,
        nullifier_seed: Value<PastaFp>,
        photo: [Value<PastaFp>; 32],
    ) -> Result<AssignedCell<PastaFp, PastaFp>, Error> {
        let (nullifier_seed_cell, photo_cells) = self.load_private_inputs(layouter.namespace(|| "load inputs"), nullifier_seed, photo)?;

        let poseidon_chip_16 = PoseidonChip::<_, 16, 8, 16>::construct(self.config.poseidon_config_16.clone());

        let first16_hash = poseidon_chip_16.hash(
            layouter.namespace(|| "first 16 hash"),
            &photo_cells[..16].try_into().unwrap(),
        )?;

        let last16_hash = poseidon_chip_16.hash(
            layouter.namespace(|| "last 16 hash"),
            &photo_cells[16..].try_into().unwrap(),
        )?;

        let poseidon_chip_3 = PoseidonChip::<_, 3, 3, 3>::construct(self.config.poseidon_config_3.clone());

        let final_hash = poseidon_chip_3.hash(
            layouter.namespace(|| "final hash"),
            &[nullifier_seed_cell, first16_hash, last16_hash].try_into().unwrap(),
        )?;

        layouter.assign_region(
            || "output",
            |mut region| {
                final_hash.copy_advice(
                    || "output",
                    &mut region,
                    self.config.output,
                    0,
                )
            },
        )?;
        
        Ok(final_hash)
    }
}


/*use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_base::halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    inputs: Vec<Column<Advice>>,
    instance: Column<Instance>,
    pow5_config: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Debug, Clone)]
pub struct PoseidonChip<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> {
    config: PoseidonConfig<WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> PoseidonChip<S, WIDTH, RATE, L> {
    pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> PoseidonConfig<WIDTH, RATE, L> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let instance = meta.instance_column();
        for i in 0..WIDTH {
            meta.enable_equality(state[i]);
        }
        meta.enable_equality(instance);
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox.try_into().unwrap(),
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig {
            inputs: state.clone().try_into().unwrap(),
            instance,
            pow5_config: pow5_config,
        }
    }

    pub fn load_private_inputs(
        &self,
        mut layouter: impl Layouter<Fp>,
        inputs: &[Value<Fp>],
    ) -> Result<Vec<AssignedCell<Fp, Fp>>, Error> {
        layouter.assign_region(
            || "load private inputs",
            |mut region| {
                inputs.iter().enumerate().map(|(i, x)| {
                    region.assign_advice(
                        || format!("private input {}", i),
                        self.config.inputs[i],
                        0,
                        || x.clone(),
                    )
                }).collect()
            },
        )
    }

    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        words: &[AssignedCell<Fp, Fp>],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());
        let word_cells = layouter.assign_region(
            || "load words",
            |mut region| {
                words.iter().enumerate().map(|(i, word)| {
                    word.copy_advice(
                        || format!("word {}", i),
                        &mut region,
                        self.config.inputs[i],
                        0,
                    )
                }).collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>()
            },
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<WIDTH>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), &word_cells)
    }
}

#[derive(Debug, Clone)]
pub struct NullifierConfig {
    photo_inputs: Vec<Column<Advice>>,
    nullifier_seed: Column<Advice>,
    output: Column<Advice>,
    poseidon_config_16: PoseidonConfig<16, 8, 16>,
    poseidon_config_3: PoseidonConfig<3, 3, 3>,
}

#[derive(Debug, Clone)]
pub struct NullifierChip {
    config: NullifierConfig,
}

impl NullifierChip {
    pub fn construct(config: NullifierConfig) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> NullifierConfig {
        let photo_inputs = (0..32).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let nullifier_seed = meta.advice_column();
        let output = meta.advice_column();
        
        let poseidon_config_16 = PoseidonChip::<_, 16, 8, 16>::configure(meta);
        let poseidon_config_3 = PoseidonChip::<_, 3, 3, 3>::configure(meta);
        
        NullifierConfig {
            photo_inputs,
            nullifier_seed,
            output,
            poseidon_config_16,
            poseidon_config_3,
        }
    }

    pub fn load_private_inputs(
        &self,
        mut layouter: impl Layouter<Fp>,
        nullifier_seed: Value<Fp>,
        photo: [Value<Fp>; 32],
    ) -> Result<(AssignedCell<Fp, Fp>, Vec<AssignedCell<Fp, Fp>>), Error> {
        let nullifier_seed_cell = layouter.assign_region(
            || "load nullifier seed",
            |mut region| {
                region.assign_advice(
                    || "nullifier seed",
                    self.config.nullifier_seed,
                    0,
                    || nullifier_seed.clone(),
                )
            },
        )?;

        let photo_cells = layouter.assign_region(
            || "load photo inputs",
            |mut region| {
                photo.iter().enumerate().map(|(i, &photo)| {
                    region.assign_advice(
                        || format!("photo input {}", i),
                        self.config.photo_inputs[i],
                        0,
                        || photo.clone(),
                    )
                }).collect::<Result<Vec<_>, _>>()
            },
        )?;
        
        Ok((nullifier_seed_cell, photo_cells))
    }

    pub fn synthesize(
        &self,
        mut layouter: impl Layouter<Fp>,
        nullifier_seed: Value<Fp>,
        photo: [Value<Fp>; 32],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let (nullifier_seed_cell, photo_cells) = self.load_private_inputs(layouter.namespace(|| "load inputs"), nullifier_seed, photo)?;

        let poseidon_chip_16 = PoseidonChip::<_, 16, 8, 16>::construct(self.config.poseidon_config_16.clone());

        let first16_hash = poseidon_chip_16.hash(
            layouter.namespace(|| "first 16 hash"),
            &photo_cells[..16].try_into().unwrap(),
        )?;

        let last16_hash = poseidon_chip_16.hash(
            layouter.namespace(|| "last 16 hash"),
            &photo_cells[16..].try_into().unwrap(),
        )?;

        let poseidon_chip_3 = PoseidonChip::<_, 3, 3, 3>::construct(self.config.poseidon_config_3.clone());

        let final_hash = poseidon_chip_3.hash(
            layouter.namespace(|| "final hash"),
            &[nullifier_seed_cell, first16_hash, last16_hash].try_into().unwrap(),
        )?;

        layouter.assign_region(
            || "output",
            |mut region| {
                final_hash.copy_advice(
                    || "output",
                    &mut region,
                    self.config.output,
                    0,
                )
            },
        )?;
        
        Ok(final_hash)
    }
}*/


/*use halo2_base::{
    gates::RangeInstructions, 
    halo2_proofs::poly::Error, 
    safe_types::{VarLenBytes, VarLenBytesVec}, 
    utils::{PrimeField, ScalarField}, 
    AssignedValue, Context
};
use crate::poseidon::hasher::{OptimizedPoseidonSpec, PoseidonHasher};

use poseidon::{PoseidonChip, PoseidonInstructions, PoseidonHasher};
//use crate::nullifier::RangeChip;
//use itertools::Itertools;

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
        let spec = OptimizedPoseidonSpec::<F, 3, 2>::default();
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
}*/

/*#[cfg(test)]
mod test {
    // Import necessary crates and modules
    use halo2_base::{
        halo2_proofs::dev::MockProver, 
        halo2_proofs::halo2curves::secp256k1::Fp, 
        AssignedValue
    };
    //use halo2_ecc::fields::{FpChip};
    //use crate::nullifier::{PoseidonChip, RangeChip};
    //use halo2_poseidon::{OptimizedPoseidonSpec, PoseidonChip};

    // Import your Nullifier struct and other necessary items
    use crate::nullifier::{self, PoseidonChip, RangeChip}; 

    // Define a test function
    #[test]
    fn test_nullifier_calculation() {
        // Initialize a Halo2 context (MockProver for testing purposes)
        let mut prover = MockProver::<Fp>::new();

        // Setup components (RangeChip and Poseidon hasher)
        let spec = OptimizedPoseidonSpec::<Fp, 3, 2>::default();
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
        let nullifier = nullifier::Nullifier::new(nullifier_seed, photo.clone());

        // Calculate the nullifier hash
        let result = nullifier.calculate_nullifier(&mut prover.context());
        assert!(result.is_ok(), "Nullifier calculation failed: {:?}", result.err());

        // Optionally, verify the nullifier hash against expected values
        let expected_hash = result.unwrap();
        let expected_value = Fp::from(123456789); // Example expected nullifier hash value
        assert_eq!(expected_hash.value(), &expected_value);
    }
}*/