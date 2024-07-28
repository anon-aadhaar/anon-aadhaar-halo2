/*use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

pub struct PhotoExtractorConfig {
    q_enable: Selector,
    n_delimited_data: Column<Advice>,
    start_delimiter_index: Column<Advice>,
    end_index: Column<Advice>,
    out: Vec<Column<Advice>>,
    photo_position: Expression<F>,
}

pub struct PhotoExtractorCircuit<F: FieldExt> {
    pub n_delimited_data: Vec<Value<F>>,
    pub start_delimiter_index: Value<F>,
    pub end_index: Value<F>,
}

impl<F: FieldExt> Circuit<F> for PhotoExtractorCircuit<F> {
    type Config = PhotoExtractorConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            n_delimited_data: vec![Value::unknown(); self.n_delimited_data.len()],
            start_delimiter_index: Value::unknown(),
            end_index: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.selector();
        let n_delimited_data = meta.advice_column();
        let start_delimiter_index = meta.advice_column();
        let end_index = meta.advice_column();
        
        // Assuming photoPackSize() returns a constant number
        const PHOTO_PACK_SIZE: usize = 33;
        let out: Vec<Column<Advice>> = (0..PHOTO_PACK_SIZE)
            .map(|_| meta.advice_column())
            .collect();

        for &column in &out {
            meta.enable_equality(column);
        }

        meta.create_gate("photo extraction", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let n_delimited_data = meta.query_advice(n_delimited_data, Rotation::cur());
            let start_delimiter_index = meta.query_advice(start_delimiter_index, Rotation::cur());
            let end_index = meta.query_advice(end_index, Rotation::cur());

            // Photo byte position validation
            let photo_position = meta.query_advice(n_delimited_data, Rotation::cur()); // This needs to be implemented based on the data structure

            let start_delimiter_validation = n_delimited_data[start_delimiter_index as usize] - (photo_position * 255);

            vec![
                q_enable * start_delimiter_validation,
            ]
        });

        PhotoExtractorConfig {
            q_enable,
            n_delimited_data,
            start_delimiter_index,
            end_index,
            out,
            photo_position: Expression::Constant(F::from(12)), // This should be set to the actual photo position
        }
    }

    fn synthesize(
        &self,
        config: PhotoExtractorConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "photo extraction",
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
                    || "end_index",
                    config.end_index,
                    offset,
                    || self.end_index.ok_or(Error::SynthesisError),
                )?;

                // Shift the data to the right to until the photo index
                // The following code assumes `SelectSubArray` has been implemented
                let sub_array = self.n_delimited_data[start_index.get()..=end_index.get()]
                    .iter()
                    .copied()
                    .collect::<Vec<_>>();
                
                let bytes_length = sub_array.len();
                let mut shifted_bytes = vec![Value::unknown(); bytes_length];
                for (i, &byte) in sub_array.iter().enumerate() {
                    shifted_bytes[i] = byte;
                }

                // Assert that the first byte is the delimiter (255 * position of name field)
                assert_eq!(shifted_bytes[0], config.photo_position * 255);

                // Pack byte[] to int[]
                let mut out_ints = vec![Value::unknown(); PHOTO_PACK_SIZE];
                let photo_max_length = PHOTO_PACK_SIZE * 31; // assuming maxFieldByteSize() returns 31
                for i in 0..PHOTO_PACK_SIZE {
                    let mut int_value = F::zero();
                    for j in 0..31 {
                        if i * 31 + j < shifted_bytes.len() {
                            int_value += shifted_bytes[i * 31 + j].get() * F::from(1u64 << (8 * j as u64));
                        }
                    }
                    out_ints[i] = Value::known(int_value);
                }

                for (i, &out) in config.out.iter().enumerate() {
                    region.assign_advice(
                        || format!("out_{}", i),
                        out,
                        offset,
                        || out_ints[i].ok_or(Error::SynthesisError),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<F: FieldExt> PhotoExtractorCircuit<F> {
    pub fn new(
        n_delimited_data: Vec<Value<F>>,
        start_delimiter_index: Value<F>,
        end_index: Value<F>,
    ) -> Self {
        Self {
            n_delimited_data,
            start_delimiter_index,
            end_index,
        }
    }
}*/
