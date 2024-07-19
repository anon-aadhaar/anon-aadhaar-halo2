/*use halo2_base::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error, Selector, Column, Advice, Instance},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
struct ExtractAndPackAsIntConfig {
    advice: [Column<Advice>; 4],
    instance: Column<Instance>,
    selector: Selector,
}

struct ExtractAndPackAsIntCircuit<F: FieldExt> {
    n_delimited_data: Vec<Value<F>>,
    delimiter_indices: Vec<Value<F>>,
    extract_position: usize,
    extract_max_length: usize,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Circuit<F> for ExtractAndPackAsIntCircuit<F> {
    type Config = ExtractAndPackAsIntConfig;

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
        ];
        let instance = cs.instance_column();
        let selector = cs.selector();

        for column in &advice {
            cs.enable_equality(*column);
        }
        cs.enable_equality(instance);

        cs.create_gate("extract and pack as int", |meta| {
            let s = meta.query_selector(selector);
            let n_delimited_data_cur = meta.query_advice(advice[0], Rotation::cur());
            let delimiter_indices_cur = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            let packed_data = meta.query_advice(advice[3], Rotation::cur());

            let start_delimiter_index = meta.query_advice(advice[0], Rotation::prev());
            let end_delimiter_index = meta.query_advice(advice[1], Rotation::prev());

            let mut constraints = Vec::new();

            // Assert that the first byte is the delimiter (255 * position of the field)
            constraints.push(s.clone() * (n_delimited_data_cur - F::from((self.extract_position * 255) as u64)));

            // Assert that last byte is the delimiter (255 * (position of the field + 1))
            constraints.push(s.clone() * (out - F::from(((self.extract_position + 1) * 255) as u64)));

            // Pack the bytes into an integer
            let mut packed_value = F::zero();
            let mut power = F::one();

            for i in 0..self.extract_max_length {
                let byte_value = meta.query_advice(advice[3], Rotation(i as i32));
                packed_value += byte_value * power;
                power *= F::from(256); // Each byte shift
            }

            constraints.push(s * (packed_value - packed_data));

            constraints
        });

        ExtractAndPackAsIntConfig {
            advice,
            instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: ExtractAndPackAsIntConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "extract and pack as int region",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let start_index = self.delimiter_indices[self.extract_position - 1];
                let end_index = self.delimiter_indices[self.extract_position];

                for (i, value) in self.n_delimited_data.iter().enumerate() {
                    region.assign_advice(
                        || format!("n delimited data {}", i),
                        config.advice[0],
                        i,
                        || *value,
                    )?;
                }

                for (i, value) in self.delimiter_indices.iter().enumerate() {
                    region.assign_advice(
                        || format!("delimiter indices {}", i),
                        config.advice[1],
                        i,
                        || *value,
                    )?;
                }

                let n_delimited_data_cur = region.assign_advice(
                    || "n delimited data cur",
                    config.advice[0],
                    0,
                    || self.n_delimited_data[start_index.get()? as usize],
                )?;

                let delimiter_indices_cur = region.assign_advice(
                    || "delimiter indices cur",
                    config.advice[1],
                    0,
                    || self.delimiter_indices[start_index.get()? as usize],
                )?;

                let out = region.assign_advice(
                    || "out",
                    config.advice[2],
                    0,
                    || Value::known(F::from(((self.extract_position + 1) * 255) as u64)),
                )?;

                let mut packed_value = F::zero();
                let mut power = F::one();
                
                for i in 0..self.extract_max_length {
                    let byte_value = self.n_delimited_data[start_index.get()? as usize + i + 1];
                    region.assign_advice(
                        || format!("shifted bytes {}", i),
                        config.advice[3],
                        i,
                        || byte_value,
                    )?;
                    packed_value += byte_value.get()? * power;
                    power *= F::from(256); // Each byte shift
                }

                region.assign_advice(
                    || "packed data",
                    config.advice[3],
                    0,
                    || Value::known(packed_value),
                )?;

                region.constrain_equal(out.cell(), config.instance)?;

                Ok(())
            },
        )
    }
}

fn main() {
    let k = 4;
    let n_delimited_data = vec![Some(5), Some(10), Some(15), Some(255), Some(1), Some(2)];
    let delimiter_indices = vec![Some(1), Some(2), Some(3)];

    let circuit = ExtractAndPackAsIntCircuit {
        n_delimited_data: n_delimited_data.iter().map(|&v| Value::known(F::from(v.unwrap()))).collect(),
        delimiter_indices: delimiter_indices.iter().map(|&v| Value::known(F::from(v.unwrap()))).collect(),
        extract_position: 1, // Example value
        extract_max_length: 31, // Example value
        _marker: PhantomData,
    };

    let public_inputs = vec![Some(5).into()]; // Example

    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    prover.assert_satisfied();
}*/
