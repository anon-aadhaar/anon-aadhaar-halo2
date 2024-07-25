use halo2_base::halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector}, 
};
//use std::sync::Arc;

use halo2_base::utils::PrimeField;

#[derive(Debug, Clone, Default)]
pub struct TimestampCircuit<F: PrimeField> {
    year: Option<F>,
    month: Option<F>,
    day: Option<F>,
    hour: Option<F>,
    minute: Option<F>,
    second: Option<F>,
}

#[derive(Debug, Clone)]
pub struct TimestampConfig {
    sel: Selector,
    year: Column<Advice>,
    month: Column<Advice>,
    day: Column<Advice>,
    hour: Column<Advice>,
    minute: Column<Advice>,
    second: Column<Advice>,
    timestamp: Column<Advice>,
}

impl<F: PrimeField> TimestampCircuit<F> {
    pub fn new(
        year: Option<F>,
        month: Option<F>,
        day: Option<F>,
        hour: Option<F>,
        minute: Option<F>,
        second: Option<F>,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}

impl<F: PrimeField> Circuit<F> for TimestampCircuit<F> {
    type Config = TimestampConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let sel = meta.selector();

        let year = meta.advice_column();
        let month = meta.advice_column();
        let day = meta.advice_column();
        let hour = meta.advice_column();
        let minute = meta.advice_column();
        let second = meta.advice_column();
        let timestamp = meta.advice_column();

        // Constraints to ensure the inputs are within valid ranges
        /*meta.create_gate("year range", |meta| {
            let sel = meta.query_selector(sel);
            let year = meta.query_advice(year, Rotation::cur());

            vec![
                sel.clone() * (year.clone() - Constant(F::from(1970))),
                sel.clone() * (Constant(F::from(2100)) - year.clone()), // assuming max year as 2100
            ]
        });*/

        /*meta.create_gate("month range", |meta| {
            let sel = meta.query_selector(sel);
            let month = meta.query_advice(month, Rotation::cur());
            let min_month = F::one();
            //let max_month = F::from(12u64);

            vec![
                sel.clone() * (month.clone() - Expression::Constant(min_month.clone())),
                //sel.clone() * (Constant(max_month) - month.clone()),
            ]
        });*/

        /*meta.create_gate("day range", |meta| {
            let sel = meta.query_selector(sel);
            let day = meta.query_advice(day, Rotation::cur());

            vec![
                sel * (day.clone() - Constant(F::from(1))) * (Constant(F::from(31)) - day),
            ]
        });

        meta.create_gate("hour range", |meta| {
            let sel = meta.query_selector(sel);
            let hour = meta.query_advice(hour, Rotation::cur());

            vec![
                sel * (hour.clone() - Constant(F::from(0))) * (Constant(F::from(23)) - hour),
            ]
        });

        meta.create_gate("minute range", |meta| {
            let sel = meta.query_selector(sel);
            let minute = meta.query_advice(minute, Rotation::cur());

            vec![
                sel * (minute.clone() - Constant(F::from(0))) * (Constant(F::from(59)) - minute),
            ]
        });

        meta.create_gate("second range", |meta| {
            let sel = meta.query_selector(sel);
            let second = meta.query_advice(second, Rotation::cur());

            vec![
                sel * (second.clone() - Constant(F::from(0))) * (Constant(F::from(59)) - second),
            ]
        });*/

        TimestampConfig {
            sel,
            year,
            month,
            day,
            hour,
            minute,
            second,
            timestamp,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "timestamp calculation",
            |mut region| {
                config.sel.enable(&mut region, 0)?;

                region.assign_advice(
                    || "year",
                    config.year,
                    0,
                    || Value::known(self.year.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "month",
                    config.month,
                    0,
                    || Value::known(self.month.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "day",
                    config.day,
                    0,
                    || Value::known(self.day.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "hour",
                    config.hour,
                    0,
                    || Value::known(self.hour.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "minute",
                    config.minute,
                    0,
                    || Value::known(self.minute.ok_or(Error::Synthesis).unwrap()),
                )?;
                region.assign_advice(
                    || "second",
                    config.second,
                    0,
                    || Value::known(self.second.ok_or(Error::Synthesis).unwrap()),
                )?;

                // Days in each month
                let days_till_previous_month: [F; 12] = [
                    F::from(0u64),
                    F::from(31u64),
                    F::from(59u64),
                    F::from(90u64),
                    F::from(120u64),
                    F::from(151u64),
                    F::from(181u64),
                    F::from(212u64),
                    F::from(243u64),
                    F::from(273u64),
                    F::from(304u64),
                    F::from(334u64),
                ];

                // Calculate leap years
                let leap_years_before = |year: u64| -> u64 {
                    (year - 1969) / 4 - (year - 1901) / 100 + (year - 1601) / 400
                };

                let year_val = self.year.map(|year| year.get_lower_32() as u64).unwrap_or(0);
                let month_val = self.month.map(|month| month.get_lower_32() as u64).unwrap_or(0);
                let day_val = self.day.map(|day| day.get_lower_32() as u64).unwrap_or(0);
                let hour_val = self.hour.map(|hour| hour.get_lower_32() as u64).unwrap_or(0);
                let minute_val = self.minute.map(|minute| minute.get_lower_32() as u64).unwrap_or(0);
                let second_val = self.second.map(|second| second.get_lower_32() as u64).unwrap_or(0);

                let days_passed = Value::known(F::from((year_val - 1970) * 365 + leap_years_before(year_val)))
                    .and_then(|days| Value::known(days + F::from(days_till_previous_month[(month_val - 1) as usize])))
                    .and_then(|days| Value::known(days + F::from(day_val - 1)));

                // Convert days to seconds and add hours, minutes, and seconds
                let total_seconds = days_passed
                    .map(|d| d * F::from(86400u64))
                    .and_then(|t| Value::known(t) + Value::known(F::from(hour_val * 3600)))
                    .and_then(|t| Value::known(t) + Value::known(F::from(minute_val * 60)))
                    .and_then(|t| Value::known(t) + Value::known(F::from(second_val)));

                // Expose the total seconds as a public output
                region.assign_advice(
                    || "timestamp",
                    config.timestamp,
                    0,
                    || total_seconds,
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn test_timestamp_circuit() {
        let k = 6;
        let circuit = TimestampCircuit {
            year: Some(Fp::from(2023u64)),
            month: Some(Fp::from(7u64)),
            day: Some(Fp::from(8u64)),
            hour: Some(Fp::from(12u64)),
            minute: Some(Fp::from(34u64)),
            second: Some(Fp::from(56u64)),
        };

        let public_inputs = vec![];

        let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}


