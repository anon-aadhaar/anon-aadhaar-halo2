/*use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
};

pub struct GenderExtractorConfig {
    q_enable: Selector,
    n_delimited_data_shifted_to_dob: Column<Advice>,
    out: Column<Advice>,
    gender_position: Expression<F>,
}

pub struct GenderExtractorCircuit<F: FieldExt> {
    pub n_delimited_data_shifted_to_dob: Vec<Value<F>>,
}

impl<F: FieldExt> Circuit<F> for GenderExtractorCircuit<F> {
    type Config = GenderExtractorConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            n_delimited_data_shifted_to_dob: vec![Value::unknown(); self.n_delimited_data_shifted_to_dob.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.selector();
        let n_delimited_data_shifted_to_dob = meta.advice_column();
        let out = meta.advice_column();

        meta.enable_equality(n_delimited_data_shifted_to_dob);
        meta.enable_equality(out);

        meta.create_gate("gender extraction", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let n_delimited_data_shifted_to_dob = meta.query_advice(n_delimited_data_shifted_to_dob, Rotation::cur());

            // Gender byte position validation
            let gender_position_validation_1 = n_delimited_data_shifted_to_dob[11] - (gender_position() * 255);
            let gender_position_validation_2 = n_delimited_data_shifted_to_dob[13] - ((gender_position() + 1) * 255);

            vec![
                q_enable.clone() * gender_position_validation_1,
                q_enable * gender_position_validation_2,
            ]
        });

        GenderExtractorConfig {
            q_enable,
            n_delimited_data_shifted_to_dob,
            out,
            gender_position: Expression::Constant(F::from(12)),
        }
    }

    fn synthesize(
        &self,
        config: GenderExtractorConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "gender extraction",
            |mut region| {
                let offset = 0;

                config.q_enable.enable(&mut region, offset)?;

                for (i, &data) in self.n_delimited_data_shifted_to_dob.iter().enumerate() {
                    region.assign_advice(
                        || format!("n_delimited_data_shifted_to_dob_{}", i),
                        config.n_delimited_data_shifted_to_dob,
                        offset + i,
                        || data.ok_or(Error::SynthesisError),
                    )?;
                }

                // Gender byte
                let gender = region.assign_advice(
                    || "gender",
                    config.out,
                    offset,
                    || self.n_delimited_data_shifted_to_dob[12].ok_or(Error::SynthesisError),
                )?;

                Ok(())
            },
        )
    }
}

impl<F: FieldExt> GenderExtractorCircuit<F> {
    pub fn new(n_delimited_data_shifted_to_dob: Vec<Value<F>>) -> Self {
        Self { n_delimited_data_shifted_to_dob }
    }
}*/
