use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    plonk::{Advice, Assignment, Circuit, Column, ConstraintSystem, Error},
    poly::Rotation,
};
use curve25519_dalek::scalar::Scalar;

struct DigitBytesToTimestampConfig {
    pub max_years: Column<Advice>,
    pub days_passed: Column<Advice>,
    pub total_days_passed: Column<Advice>,
    pub year: Column<Advice>,
    pub month: Column<Advice>,
    pub day: Column<Advice>,
    pub hour: Column<Advice>,
    pub minute: Column<Advice>,
    pub second: Column<Advice>,
    pub out: Column<Advice>,
}

struct DigitBytesToTimestamp {
    year: Scalar,
    month: Scalar,
    day: Scalar,
    hour: Scalar,
    minute: Scalar,
    second: Scalar,
}

impl<F: FieldExt> Circuit<F> for DigitBytesToTimestamp {
    type Config = DigitBytesToTimestampConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // Define your configuration and constraints here
        let days_till_previous_month = meta.advice_column();
        let days_passed = meta.advice_column();
        let total_days_passed = meta.advice_column();
        let year = meta.advice_column();
        let month = meta.advice_column();
        let day = meta.advice_column();
        let hour = meta.advice_column();
        let minute = meta.advice_column();
        let second = meta.advice_column();
        let out = meta.advice_column();

        meta.enable_equality(days_till_previous_month);
        meta.enable_equality(days_passed);
        meta.enable_equality(total_days_passed);
        meta.enable_equality(year);
        meta.enable_equality(month);
        meta.enable_equality(day);
        meta.enable_equality(hour);
        meta.enable_equality(minute);
        meta.enable_equality(second);
        meta.enable_equality(out);

        DigitBytesToTimestampConfig {
            max_years,
            days_passed,
            total_days_passed,
            year,
            month,
            day,
            hour,
            minute,
            second,
            out,
        }
    }

    fn synthesize(
        &self,
        cs: &mut impl Assignment<F>,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Assign input values to advice columns
        let year = cs.assign_advice(
            || "year",
            config.year,
            0,
            || Ok(F::from(self.year.to_bytes()[0] as u64)),
        )?;

        let month = cs.assign_advice(
            || "month",
            config.month,
            0,
            || Ok(F::from(self.month.to_bytes()[0] as u64)),
        )?;

        let day = cs.assign_advice(
            || "day",
            config.day,
            0,
            || Ok(F::from(self.day.to_bytes()[0] as u64)),
        )?;

        let hour = cs.assign_advice(
            || "hour",
            config.hour,
            0,
            || Ok(F::from(self.hour.to_bytes()[0] as u64)),
        )?;

        let minute = cs.assign_advice(
            || "minute",
            config.minute,
            0,
            || Ok(F::from(self.minute.to_bytes()[0] as u64)),
        )?;

        let second = cs.assign_advice(
            || "second",
            config.second,
            0,
            || Ok(F::from(self.second.to_bytes()[0] as u64)),
        )?;

        // These do not add constraints, but can help to catch errors during witness generation
        cs.create_gate("date_time_constraints", |meta| {
            let year = meta.query_advice(config.year, Rotation::cur());
            let month = meta.query_advice(config.month, Rotation::cur());
            let day = meta.query_advice(config.day, Rotation::cur());
            let hour = meta.query_advice(config.hour, Rotation::cur());
            let minute = meta.query_advice(config.minute, Rotation::cur());
            let second = meta.query_advice(config.second, Rotation::cur());
            let max_years = F::from(config.max_years);  // max_years should be provided as a constant
        
            let zero = F::zero();
            let one = F::one();
            let twelve = F::from(12);
            let thirty_one = F::from(31);
            let twenty_three = F::from(23);
            let fifty_nine = F::from(59);
            let nineteen_seventy = F::from(1970);
            let one_month = F::from(1);
            let one_day = F::from(1);
        
            vec![
                // year >= 1970
                (year.clone() - nineteen_seventy.clone() + one.clone(), one.clone()),
                // year <= maxYears
                (max_years.clone() - year.clone() + one.clone(), one.clone()),
        
                // month >= 1
                (month.clone() - one_month.clone(), zero.clone()),
        
                // month <= 12
                (twelve.clone() - month.clone() + one.clone(), one.clone()),
        
                // day >= 1
                (day.clone() - one_day.clone(), zero.clone()),
        
                // day <= 31
                (thirty_one.clone() - day.clone() + one.clone(), one.clone()),
        
                // hour >= 0
                (hour.clone(), zero.clone()),
        
                // hour <= 23
                (twenty_three.clone() - hour.clone() + one.clone(), one.clone()),
        
                // minute >= 0
                (minute.clone(), zero.clone()),
        
                // minute <= 59
                (fifty_nine.clone() - minute.clone() + one.clone(), one.clone()),
        
                // second >= 0
                (second.clone(), zero.clone()),
        
                // second <= 59
                (fifty_nine.clone() - second.clone() + one.clone(), one.clone()),
            ]
        })?;
        
        cs.create_gate("calculate_out", |meta| {
            let total_days_passed = meta.query_advice(config.total_days_passed, Rotation::cur());
            let hour = meta.query_advice(config.hour, Rotation::cur());
            let minute = meta.query_advice(config.minute, Rotation::cur());
            let second = meta.query_advice(config.second, Rotation::cur());
            let out = meta.query_advice(config.out, Rotation::cur());
        
            let days_in_seconds = F::from(86400);
            let hours_in_seconds = F::from(3600);
            let minutes_in_seconds = F::from(60);
        
            // Calculate out = totalDaysPassed * 86400 + hour * 3600 + minute * 60 + second
            let expected_out = total_days_passed * days_in_seconds 
                               + hour * hours_in_seconds 
                               + minute * minutes_in_seconds 
                               + second;
        
            vec![
                (out - expected_out, F::zero())
            ]
        })?;        

        Ok(())
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

    let year_offset = year.value().unwrap() - 1970;
    let mut days_passed = vec![year_offset * 365];
    days_passed.push(day.value().unwrap() - 1);

    let mut is_current_month = vec![];
    for i in 0..12 {
        let is_equal = (month.value().unwrap() - 1) == i;
        is_current_month.push(is_equal);

        let days_till_month = if is_equal { days_till_previous_month[i] } else { 0 };
        days_passed.push(days_till_month);
    }

    let max_years = year_offset;
    let max_leap_years = max_years / 4;

    let mut is_leap_year_less_than_current_year = vec![];
    let mut is_leap_year_current_year = vec![];
    let mut is_current_month_after_feb = vec![];

    for i in 0..max_leap_years {
        let less_than_current_year = year_offset >= (i * 4) + 2;
        is_leap_year_less_than_current_year.push(less_than_current_year);

        let current_year = year_offset == (i * 4) + 2;
        is_leap_year_current_year.push(current_year);

        let after_feb = month.value().unwrap() > 2;
        is_current_month_after_feb.push(after_feb);

        let leap_day_added = if less_than_current_year { 1 } else { 0 };
        days_passed.push(leap_day_added);

        let current_leap_day = if current_year && after_feb { 1 } else { 0 };
        days_passed.push(current_leap_day);
    }

    // Summing up all days passed
    let mut total_days_passed = days_passed[0];
    for i in 1..days_passed.len() {
        total_days_passed += days_passed[i];
    }

    let total_days_passed = cs.assign_advice(
        || "total_days_passed",
        config.total_days_passed,
        0,
        || Ok(F::from(total_days_passed)), 
    )?;

    Ok(total_days_passed)
}
