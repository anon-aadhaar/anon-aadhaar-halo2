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

/*#[derive(Debug, Clone)]
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
        
        let poseidon_config_16 = PoseidonChip::<P128Pow5T3, 16, 8, 16>::configure(meta);
        let poseidon_config_3 = PoseidonChip::<P128Pow5T3, 3, 3, 3>::configure(meta);
        
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

        let poseidon_chip_16 = PoseidonChip::<P128Pow5T3, 16, 8, 16>::construct(self.config.poseidon_config_16.clone());

        let first16_hash = poseidon_chip_16.hash(
            layouter.namespace(|| "first 16 hash"),
            &photo_cells[..16].try_into().unwrap(),
        )?;

        let last16_hash = poseidon_chip_16.hash(
            layouter.namespace(|| "last 16 hash"),
            &photo_cells[16..].try_into().unwrap(),
        )?;

        let poseidon_chip_3 = PoseidonChip::<P128Pow5T3, 3, 3, 3>::construct(self.config.poseidon_config_3.clone());

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


#[derive(Debug, Clone)]
struct NullifierCircuit {
    nullifier_seed: Value<PastaFp>,
    photo: [Value<PastaFp>; 32],
}

impl NullifierCircuit {
    fn new(nullifier_seed: PastaFp, photo: [PastaFp; 32]) -> Self {
        Self {
            nullifier_seed: Value::known(nullifier_seed),
            photo: photo.map(Value::known),
        }
    }
}

impl Circuit<PastaFp> for NullifierCircuit {
    type Config = NullifierConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<PastaFp>) -> Self::Config {
        NullifierChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<PastaFp>,
    ) -> Result<(), Error> {
        let nullifier_chip = NullifierChip::construct(config);

        // Synthesize the nullifier chip using the provided inputs
        let _ = nullifier_chip.synthesize(
            layouter.namespace(|| "synthesize nullifier"),
            self.nullifier_seed,
            self.photo,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;
    use halo2curves::pasta::Fp as PastaFp;

    #[test]
    fn test_nullifier_circuit() {
        // Initialize test inputs
        let nullifier_seed = PastaFp::from(12345678);
        let photo: [PastaFp; 32] = (0..32).map(|i| PastaFp::from(i as u64)).collect::<Vec<_>>().try_into().unwrap();

        // Create the circuit
        let circuit = NullifierCircuit::new(nullifier_seed, photo);

        // Create a MockProver instance
        let k = 8;
        let mut public_inputs = vec![];

        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
