use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Assignment, Circuit, Column, ConstraintSystem, Error, Expression, Instance},
    poly::Rotation,
};
use halo2_base::halo2_proofs::plonk::Expression::Constant as Constant;

#[derive(Clone)]
struct DigitBytesToTimestampConfig {
    year: Column<Advice>,
    month: Column<Advice>,
    day: Column<Advice>,
    hour: Column<Advice>,
    minute: Column<Advice>,
    second: Column<Advice>,
    out: Column<Instance>,
    total_days_passed: Column<Advice>
}

#[derive(Clone)]
struct DigitBytesToTimestamp {
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
    out: u64
}

impl DigitBytesToTimestamp {
    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let year = meta.advice_column();
        let month = meta.advice_column();
        let day = meta.advice_column();
        let hour = meta.advice_column();
        let minute = meta.advice_column();
        let second = meta.advice_column();
        let out = meta.instance_column();
        let total_days_passed = meta.advice_column();

        meta.create_gate("date_time_constraints", |meta| {
            let year = meta.query_advice(year, Rotation::cur());
            let month = meta.query_advice(month, Rotation::cur());
            let day = meta.query_advice(day, Rotation::cur());
            let hour = meta.query_advice(hour, Rotation::cur());
            let minute = meta.query_advice(minute, Rotation::cur());
            let second = meta.query_advice(second, Rotation::cur());
            let max_years = F::from(2050); // Replace with appropriate value

            let zero = F::zero();
            let one = F::one();
            let twelve = F::from(12);
            let thirty_one = F::from(31);
            let twenty_three = F::from(23);
            let fifty_nine = F::from(59);
            let nineteen_seventy = F::from(1970);

            vec![
                ("year range", year.clone() - Expression::Constant(nineteen_seventy)),
                ("year range", Expression::Constant(max_years.clone()) - year.clone()), 
                ("month range", month.clone() - Expression::Constant(one.clone())),
                ("month range", Expression::Constant(twelve) - month.clone()),
                ("day range", day.clone() - Expression::Constant(one.clone())),
                ("day range", Expression::Constant(thirty_one) - day.clone()),
                ("hour range", hour.clone() - Expression::Constant(zero.clone())),
                ("hour range", Expression::Constant(twenty_three) - hour.clone()),
                ("minute range", minute.clone() - Expression::Constant(zero.clone())),
                ("minute range", Expression::Constant(fifty_nine.clone()) - minute.clone()),
                ("second range", second.clone() - Expression::Constant(zero.clone())),
                ("second range", Expression::Constant(fifty_nine) - second.clone()),
            ]
        });

        meta.create_gate("calculate_out", |meta| {
            let hour = meta.query_advice(hour, Rotation::cur());
            let minute = meta.query_advice(minute, Rotation::cur());
            let second = meta.query_advice(second, Rotation::cur());
            let out = meta.query_instance(out, Rotation::cur());
            let total_days_passed = meta.query_advice(total_days_passed, Rotation::cur());

            let days_in_seconds = F::from(86400);
            let hours_in_seconds = F::from(3600);
            let minutes_in_seconds = F::from(60);

            let year_val = Constant(year);
            let month_val = Constant(month);

            let expected_out = total_days_passed * days_in_seconds 
                               + hour * hours_in_seconds 
                               + minute * minutes_in_seconds 
                               + second;

            vec![
                ("calculate out", out - expected_out)
            ]
        });

        Self::Config {
            year,
            month,
            day,
            hour,
            minute,
            second,
            out,
            total_days_passed
        }
    }
}

fn calculate_days_passed<F: FieldExt>(
    cs: &mut impl Assignment<F>,
    config: &DigitBytesToTimestampConfig,
    year: &AssignedCell<F, F>,
    month: &AssignedCell<F, F>,
    day: &AssignedCell<F, F>,
) -> Result<AssignedCell<F, F>, Error> {
    let days_till_previous_month = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    let year_offset = year.value().map(|y| y.get_lower_32() as u64).unwrap_or(0) - 1970;
    let mut days_passed = vec![year_offset * 365];
    days_passed.push(day.value().map(|d| d.get_lower_32() as u64).unwrap_or(0) - 1);

    for i in 0..12 {
        let is_equal = month.value().map(|m| (m.get_lower_32() as u64) - 1 == i).unwrap_or(false);
        let days_till_month = if is_equal { days_till_previous_month[i] } else { 0 };
        days_passed.push(days_till_month);
    }

    let max_years = year_offset;
    let max_leap_years = max_years / 4;

    for i in 0..max_leap_years {
        let less_than_current_year = year_offset >= (i * 4) + 2;
        let current_year = year_offset == (i * 4) + 2;
        let after_feb = month.value().map(|m| m.get_lower_32() as u64 > 2).unwrap_or(false);

        let leap_day_added = if less_than_current_year { 1 } else { 0 };
        days_passed.push(leap_day_added);

        let current_leap_day = if current_year && after_feb { 1 } else { 0 };
        days_passed.push(current_leap_day);
    }

    let total_days_passed_value: u64 = days_passed.iter().sum();

    let total_days_passed = cs.assign_advice(
        || "total_days_passed",
        config.total_days_passed,
        0,
        || Ok(F::from(total_days_passed_value)),
    )?;

    Ok(total_days_passed)
}

impl<F: FieldExt> Circuit<F> for DigitBytesToTimestamp {
    type Config = DigitBytesToTimestampConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        DigitBytesToTimestampConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign values",
            |mut region| {
                let year = region.assign_advice(|| "year", config.year, 0, || Value::known(F::from(self.year)))?;
                let month = region.assign_advice(|| "month", config.month, 0, || Value::known(F::from(self.month)))?;
                let day = region.assign_advice(|| "day", config.day, 0, || Value::known(F::from(self.day)))?;
                let hour = region.assign_advice(|| "hour", config.hour, 0, || Value::known(F::from(self.hour)))?;
                let minute = region.assign_advice(|| "minute", config.minute, 0, || Value::known(F::from(self.minute)))?;
                let second = region.assign_advice(|| "second", config.second, 0, || Value::known(F::from(self.second)))?;

                let total_days_passed = calculate_days_passed(&mut region, &config, &year, &month, &day)?;

                region.assign_advice(|| "total_days_passed", config.total_days_passed, 0, || total_days_passed.value())?;

                region.assign_instance(|| "out", config.out, 0, || Value::known(F::from(self.out)))?;

                Ok(())
            },
        )?;

        Ok(())
    }
}