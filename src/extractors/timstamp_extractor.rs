use halo2_base::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value, Region, ConstraintSystem, Column, Advice, Instance},
    dev::MockProver,
    plonk::{Circuit, Error, Selector},
    poly::Rotation,
};

struct DigitBytesToIntConfig {
    selector: Selector,
    input: [Column<Advice>; 4],
    output: Column<Advice>,
}

impl DigitBytesToIntConfig {
    fn configure(cs: &mut ConstraintSystem<F>) -> Self {
        let selector = cs.selector();
        let input = [cs.advice_column(), cs.advice_column(), cs.advice_column(), cs.advice_column()];
        let output = cs.advice_column();
        
        cs.create_gate("DigitBytesToInt", |meta| {
            let s = meta.query_selector(selector);
            let inputs: Vec<_> = input.iter().map(|&col| meta.query_advice(col, Rotation::cur())).collect();
            let output = meta.query_advice(output, Rotation::cur());

            // Sum each digit multiplied by its respective place value
            let mut sum = inputs[0].clone();
            for (i, &input) in inputs.iter().enumerate().skip(1) {
                sum = sum + input * F::from(10u64.pow(i as u32));
            }

            vec![s * (sum - output)]
        });

        DigitBytesToIntConfig { selector, input, output }
    }

    fn assign_values(
        &self, 
        region: &mut Region<'_, F>, 
        offset: usize, 
        input_values: &[Value<F>; 4]
    ) -> Result<Value<F>, Error> {
        self.selector.enable(region, offset)?;

        for (i, &input_value) in input_values.iter().enumerate() {
            region.assign_advice(|| format!("input {}", i), self.input[i], offset, || input_value)?;
        }

        let output_value = input_values.iter()
            .enumerate()
            .fold(Value::known(F::zero()), |acc, (i, &val)| acc + val * F::from(10u64.pow(i as u32)));

        region.assign_advice(|| "output", self.output, offset, || output_value)?;
        Ok(output_value)
    }
}

struct TimestampExtractorConfig {
    n_delimited_data: Column<Advice>,
    timestamp: Column<Advice>,
    year: DigitBytesToIntConfig,
    month: DigitBytesToIntConfig,
    day: DigitBytesToIntConfig,
    hour: DigitBytesToIntConfig,
    date_to_unix_time: DateToUnixTimeConfig,
}

impl TimestampExtractorConfig {
    fn configure(cs: &mut ConstraintSystem<F>) -> Self {
        let n_delimited_data = cs.advice_column();
        let timestamp = cs.advice_column();

        let year = DigitBytesToIntConfig::configure(cs);
        let month = DigitBytesToIntConfig::configure(cs);
        let day = DigitBytesToIntConfig::configure(cs);
        let hour = DigitBytesToIntConfig::configure(cs);

        let date_to_unix_time = DateToUnixTimeConfig::configure(cs);

        TimestampExtractorConfig {
            n_delimited_data,
            timestamp,
            year,
            month,
            day,
            hour,
            date_to_unix_time,
        }
    }
}

struct TimestampExtractorCircuit<F: FieldExt> {
    n_delimited_data: Vec<Value<F>>,
    max_data_length: usize,
}

impl<F: FieldExt> Circuit<F> for TimestampExtractorCircuit<F> {
    type Config = TimestampExtractorConfig;

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        TimestampExtractorConfig::configure(cs)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "TimestampExtractor",
            |mut region| {
                let offset = 0;

                for (i, &data) in self.n_delimited_data.iter().enumerate() {
                    region.assign_advice(
                        || format!("n_delimited_data {}", i),
                        config.n_delimited_data,
                        i,
                        || data
                    )?;
                }

                let year = config.year.assign_values(
                    &mut region,
                    offset,
                    &[self.n_delimited_data[9], self.n_delimited_data[10], self.n_delimited_data[11], self.n_delimited_data[12]]
                )?;

                let month = config.month.assign_values(
                    &mut region,
                    offset + 1,
                    &[self.n_delimited_data[13], self.n_delimited_data[14]]
                )?;

                let day = config.day.assign_values(
                    &mut region,
                    offset + 2,
                    &[self.n_delimited_data[15], self.n_delimited_data[16]]
                )?;

                let hour = config.hour.assign_values(
                    &mut region,
                    offset + 3,
                    &[self.n_delimited_data[17], self.n_delimited_data[18]]
                )?;

                let timestamp = config.date_to_unix_time.assign_values(
                    &mut region,
                    offset + 4,
                    year, month, day, hour
                )?;

                region.assign_advice(
                    || "timestamp",
                    config.timestamp,
                    offset,
                    || timestamp - Value::known(F::from(19800))
                )?;

                Ok(())
            }
        )
    }
}

// Your DateToUnixTimeConfig and other needed configurations should be defined similarly.

fn main() {
    // Use this part for testing the circuit with real inputs
    let k = 4;

    let n_delimited_data = vec![
        Some(48), Some(49), Some(50), Some(51), Some(52), Some(53), Some(54), Some(55), 
        Some(48), Some(50), Some(48), Some(50), Some(49), Some(48), Some(48), Some(50), 
        Some(49), Some(48), Some(49), Some(50), Some(50), Some(49), Some(50), Some(49), 
        Some(50), Some(50), Some(49), Some(50), Some(49), Some(50), Some(50), Some(49), 
    ];
    let circuit = TimestampExtractorCircuit {
        n_delimited_data: n_delimited_data.iter().map(|&v| Value::known(F::from(v.unwrap()))).collect(),
        max_data_length: n_delimited_data.len(),
    };

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
    prover.assert_satisfied();
}
