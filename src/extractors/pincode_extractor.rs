/*use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

pub struct PinCodeExtractorConfig {
    q_enable: Selector,
    n_delimited_data: Column<Advice>,
    start_delimiter_index: Column<Advice>,
    end_delimiter_index: Column<Advice>,
    out: Column<Advice>,
    pin_code_position: Expression<F>,
}

pub struct PinCodeExtractorCircuit<F: FieldExt> {
    pub n_delimited_data: Vec<Value<F>>,
    pub start_delimiter_index: Value<F>,
    pub end_delimiter_index: Value<F>,
}

impl<F: FieldExt> Circuit<F> for PinCodeExtractorCircuit<F> {
    type Config = PinCodeExtractorConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            n_delimited_data: vec![Value::unknown(); self.n_delimited_data.len()],
            start_delimiter_index: Value::unknown(),
            end_delimiter_index: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.selector();
        let n_delimited_data = meta.advice_column();
        let start_delimiter_index = meta.advice_column();
        let end_delimiter_index = meta.advice_column();
        let out = meta.advice_column();

        meta.enable_equality(n_delimited_data);
        meta.enable_equality(start_delimiter_index);
        meta.enable_equality(end_delimiter_index);
        meta.enable_equality(out);

        meta.create_gate("pin code extraction", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let n_delimited_data = meta.query_advice(n_delimited_data, Rotation::cur());
            let start_delimiter_index = meta.query_advice(start_delimiter_index, Rotation::cur());
            let end_delimiter_index = meta.query_advice(end_delimiter_index, Rotation::cur());

            // Pin code byte position validation
            let pin_code_position = meta.query_advice(n_delimited_data, Rotation::cur()); // This needs to be implemented based on the data structure

            let start_delimiter_validation = n_delimited_data[start_delimiter_index as usize] - (pin_code_position * 255);
            let end_delimiter_validation = n_delimited_data[end_delimiter_index as usize] - ((pin_code_position + 1) * 255);

            vec![
                q_enable.clone() * start_delimiter_validation,
                q_enable * end_delimiter_validation,
            ]
        });

        PinCodeExtractorConfig {
            q_enable,
            n_delimited_data,
            start_delimiter_index,
            end_delimiter_index,
            out,
            pin_code_position: Expression::Constant(F::from(12)), // This should be set to the actual pin code position
        }
    }

    fn synthesize(
        &self,
        config: PinCodeExtractorConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "pin code extraction",
            |mut region| {
                let offset = 0;

                config.q_enable.enable(&mut region, offset)?;

                for (i, &data) in self.n_delimited_data.iter().enumerate() {
                    region.assign_advice(
                        || format!("n_delimited_data_{}", i),
                        config.n_delimited_data,
                        offset + i,
                        || data.ok_or(Error::SynthesisError),
                    )?;
                }

                let start_index = region.assign_advice(
                    || "start_delimiter_index",
                    config.start_delimiter_index,
                    offset,
                    || self.start_delimiter_index.ok_or(Error::SynthesisError),
                )?;

                let end_index = region.assign_advice(
                    || "end_delimiter_index",
                    config.end_delimiter_index,
                    offset,
                    || self.end_delimiter_index.ok_or(Error::SynthesisError),
                )?;

                let pin_code = region.assign_advice(
                    || "pin_code",
                    config.out,
                    offset,
                    || {
                        let mut pin_code = 0;
                        for i in 1..=6 {
                            pin_code = pin_code * 10 + self.n_delimited_data[start_index + i].unwrap();
                        }
                        Value::known(pin_code.into())
                    },
                )?;

                Ok(())
            },
        )
    }
}

impl<F: FieldExt> PinCodeExtractorCircuit<F> {
    pub fn new(
        n_delimited_data: Vec<Value<F>>,
        start_delimiter_index: Value<F>,
        end_delimiter_index: Value<F>,
    ) -> Self {
        Self {
            n_delimited_data,
            start_delimiter_index,
            end_delimiter_index,
        }
    }
}*/
