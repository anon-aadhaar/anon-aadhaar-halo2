/*use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

pub struct AgeExtractorCircuit<F: FieldExt> {
    pub n_delimited_data: Vec<Value<F>>,
    pub start_delimiter_index: Value<F>,
    pub current_year: Value<F>,
    pub current_month: Value<F>,
    pub current_day: Value<F>,
}

struct AgeExtractorConfig {
    q_enable: Selector,
    n_delimited_data: Column<Advice>,
    shifted_bytes: Column<Advice>,
    start_delimiter_index: Column<Advice>,
    current_year: Column<Advice>,
    current_month: Column<Advice>,
    current_day: Column<Advice>,
    age: Column<Advice>,
}


impl<F: FieldExt> Circuit<F> for AgeExtractorCircuit<F> {
    type Config = AgeExtractorConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            n_delimited_data: vec![Value::unknown(); self.n_delimited_data.len()],
            start_delimiter_index: Value::unknown(),
            current_year: Value::unknown(),
            current_month: Value::unknown(),
            current_day: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.selector();
        let n_delimited_data = meta.advice_column();
        let shifted_bytes = meta.advice_column();
        let start_delimiter_index = meta.advice_column();
        let current_year = meta.advice_column();
        let current_month = meta.advice_column();
        let current_day = meta.advice_column();
        let age = meta.advice_column();

        meta.enable_equality(n_delimited_data);
        meta.enable_equality(shifted_bytes);
        meta.enable_equality(start_delimiter_index);
        meta.enable_equality(current_year);
        meta.enable_equality(current_month);
        meta.enable_equality(current_day);
        meta.enable_equality(age);

        meta.create_gate("shift data", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let n_delimited_data = meta.query_advice(n_delimited_data, Rotation::cur());
            let shifted_bytes = meta.query_advice(shifted_bytes, Rotation::next());
            let start_delimiter_index = meta.query_advice(start_delimiter_index, Rotation::cur());

            // Implement the shift logic here
            vec![
                q_enable * (shifted_bytes - n_delimited_data.shifted_by(start_delimiter_index)),
            ]
        });

        // Additional constraints for date validation and age calculation
        meta.create_gate("date validation and age calculation", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let shifted_bytes = meta.query_advice(shifted_bytes, Rotation::cur());
            let current_year = meta.query_advice(current_year, Rotation::cur());
            let current_month = meta.query_advice(current_month, Rotation::cur());
            let current_day = meta.query_advice(current_day, Rotation::cur());
            let age = meta.query_advice(age, Rotation::cur());

            let year = Expression::from(shifted_bytes[7]) * 1000
                + Expression::from(shifted_bytes[8]) * 100
                + Expression::from(shifted_bytes[9]) * 10
                + Expression::from(shifted_bytes[10]);
            let month = Expression::from(shifted_bytes[4]) * 10
                + Expression::from(shifted_bytes[5]);
            let day = Expression::from(shifted_bytes[1]) * 10
                + Expression::from(shifted_bytes[2]);

            let age_by_year = current_year - year - 1;

            let month_gt = current_month - month;
            let month_eq = current_month - month;
            let day_gt = current_day - day;

            let is_higher_day_on_same_month = month_eq * day_gt;

            let final_age = age_by_year + month_gt + is_higher_day_on_same_month;

            vec![
                q_enable * (age - final_age),
            ]
        });

        AgeExtractorConfig {
            q_enable,
            n_delimited_data,
            shifted_bytes,
            start_delimiter_index,
            current_year,
            current_month,
            current_day,
            age,
        }
    }

    fn synthesize(
        &self,
        config: AgeExtractorConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "age extraction",
            |mut region: Region<'_, F>| {
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

                let start_delimiter_index = region.assign_advice(
                    || "start_delimiter_index",
                    config.start_delimiter_index,
                    offset,
                    || self.start_delimiter_index.ok_or(Error::SynthesisError),
                )?;

                let current_year = region.assign_advice(
                    || "current_year",
                    config.current_year,
                    offset,
                    || self.current_year.ok_or(Error::SynthesisError),
                )?;

                let current_month = region.assign_advice(
                    || "current_month",
                    config.current_month,
                    offset,
                    || self.current_month.ok_or(Error::SynthesisError),
                )?;

                let current_day = region.assign_advice(
                    || "current_day",
                    config.current_day,
                    offset,
                    || self.current_day.ok_or(Error::SynthesisError),
                )?;

                let shifted_bytes: Vec<AssignedCell<F, F>> = self
                    .n_delimited_data
                    .iter()
                    .enumerate()
                    .map(|(i, &data)| {
                        region.assign_advice(
                            || format!("shifted_bytes_{}", i),
                            config.shifted_bytes,
                            offset + i,
                            || {
                                let shift = start_delimiter_index.value().map(|&s| s as usize);
                                data.ok_or(Error::SynthesisError).map(|d| d.shifted_by(shift))
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                // Implement date conversion and age calculation logic
                let year = region.assign_advice(
                    || "year",
                    config.shifted_bytes,
                    offset + 7,
                    || {
                        shifted_bytes[7]
                            .value()
                            .and_then(|&b7| shifted_bytes[8].value().map(|&b8| (b7 * 1000) + (b8 * 100)))
                            .and_then(|v| shifted_bytes[9].value().map(|&b9| v + (b9 * 10)))
                            .and_then(|v| shifted_bytes[10].value().map(|&b10| v + b10))
                            .ok_or(Error::SynthesisError)
                    },
                )?;

                let month = region.assign_advice(
                    || "month",
                    config.shifted_bytes,
                    offset + 4,
                    || {
                        shifted_bytes[4]
                            .value()
                            .and_then(|&b4| shifted_bytes[5].value().map(|&b5| (b4 * 10) + b5))
                            .ok_or(Error::SynthesisError)
                    },
                )?;

                let day = region.assign_advice(
                    || "day",
                    config.shifted_bytes,
                    offset + 1,
                    || {
                        shifted_bytes[1]
                            .value()
                            .and_then(|&b1| shifted_bytes[2].value().map(|&b2| (b1 * 10) + b2))
                            .ok_or(Error::SynthesisError)
                    },
                )?;

                let age_by_year = current_year.value().map(|&cy| cy - year.value().unwrap() - 1);
                let month_gt = current_month.value().map(|&cm| cm - month.value().unwrap());
                let month_eq = current_month.value().map(|&cm| cm - month.value().unwrap());
                let day_gt = current_day.value().map(|&cd| cd - day.value().unwrap());

                let is_higher_day_on_same_month = month_eq.zip(day_gt).map(|(me, dg)| me * dg);

                let final_age = age_by_year
                    .zip(month_gt)
                    .zip(is_higher_day_on_same_month)
                    .map(|((ay, mg), ihd)| ay + mg + ihd);

                region.assign_advice(
                    || "age",
                    config.age,
                    offset,
                    || final_age.ok_or(Error::SynthesisError),
                )?;

                Ok(())
            },
        )
    }
}*/

