/*use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

// Assuming the following constants/functions are defined:
// maxDataLength, photoPackSize, photoPosition, dobPosition, statePosition, pinCodePosition, TimestampExtractor, AgeExtractor, GenderExtractor, PinCodeExtractor, ExtractAndPackAsInt, PhotoExtractor

#[derive(Clone)]
pub struct QRDataExtractorConfig {
    q_enable: Selector,
    data: Column<Advice>,
    qr_data_padded_length: Column<Advice>,
    delimiter_indices: Column<Advice>,
    timestamp: Column<Advice>,
    age_above_18: Column<Advice>,
    gender: Column<Advice>,
    state: Column<Advice>,
    pin_code: Column<Advice>,
    photo: Vec<Column<Advice>>,
    n255_filter: Column<Advice>,
    n_delimited_data: Column<Advice>,
}

pub struct QRDataExtractorCircuit<F: FieldExt> {
    pub data: Vec<Value<F>>,
    pub qr_data_padded_length: Value<F>,
    pub delimiter_indices: Vec<Value<F>>,
}

impl<F: FieldExt> Circuit<F> for QRDataExtractorCircuit<F> {
    type Config = QRDataExtractorConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            data: vec![Value::unknown(); self.data.len()],
            qr_data_padded_length: Value::unknown(),
            delimiter_indices: vec![Value::unknown(); self.delimiter_indices.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let q_enable = meta.selector();
        let data = meta.advice_column();
        let qr_data_padded_length = meta.advice_column();
        let delimiter_indices = meta.advice_column();
        let timestamp = meta.advice_column();
        let age_above_18 = meta.advice_column();
        let gender = meta.advice_column();
        let state = meta.advice_column();
        let pin_code = meta.advice_column();

        const PHOTO_PACK_SIZE: usize = 33;
        let photo: Vec<Column<Advice>> = (0..PHOTO_PACK_SIZE)
            .map(|_| meta.advice_column())
            .collect();

        for &column in &photo {
            meta.enable_equality(column);
        }

        let n255_filter = meta.advice_column();
        let n_delimited_data = meta.advice_column();

        QRDataExtractorConfig {
            q_enable,
            data,
            qr_data_padded_length,
            delimiter_indices,
            timestamp,
            age_above_18,
            gender,
            state,
            pin_code,
            photo,
            n255_filter,
            n_delimited_data,
        }
    }

    fn synthesize(
        &self,
        config: QRDataExtractorConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "QR data extraction",
            |mut region| {
                let offset = 0;

                config.q_enable.enable(&mut region, offset)?;

                for (i, &data) in self.data.iter().enumerate() {
                    region.assign_advice(
                        || format!("data_{}", i),
                        config.data,
                        offset + i,
                        || data.ok_or(Error::SynthesisError),
                    )?;
                }

                let qr_data_padded_length = region.assign_advice(
                    || "qr_data_padded_length",
                    config.qr_data_padded_length,
                    offset,
                    || self.qr_data_padded_length.ok_or(Error::SynthesisError),
                )?;

                for (i, &delimiter) in self.delimiter_indices.iter().enumerate() {
                    region.assign_advice(
                        || format!("delimiter_indices_{}", i),
                        config.delimiter_indices,
                        offset + i,
                        || delimiter.ok_or(Error::SynthesisError),
                    )?;
                }

                // Create `nDelimitedData`
                let max_data_length = self.data.len();
                let mut n255_filter = vec![Value::zero(); max_data_length + 1];
                let mut n_delimited_data = vec![Value::zero(); max_data_length];

                for i in 0..max_data_length {
                    let is_255 = self.data[i] == Value::known(F::from(255u64));
                    let index_before_photo = i < self.delimiter_indices[photoPosition() - 1].get().unwrap() as usize + 1;
                    let is_255_and_index_before_photo = is_255 * Value::known(F::from(index_before_photo as u64));

                    n255_filter[i + 1] = is_255_and_index_before_photo * Value::known(F::from(255u64)) + n255_filter[i];
                    n_delimited_data[i] = is_255_and_index_before_photo * n255_filter[i] + self.data[i];

                    region.assign_advice(
                        || format!("n255_filter_{}", i),
                        config.n255_filter,
                        offset + i,
                        || n255_filter[i].ok_or(Error::SynthesisError),
                    )?;

                    region.assign_advice(
                        || format!("n_delimited_data_{}", i),
                        config.n_delimited_data,
                        offset + i,
                        || n_delimited_data[i].ok_or(Error::SynthesisError),
                    )?;
                }

                // Extract timestamp
                let timestamp_extractor = TimestampExtractor::new(max_data_length);
                let timestamp = timestamp_extractor.extract(&mut region, &n_delimited_data)?;

                // Assign timestamp output
                region.assign_advice(
                    || "timestamp",
                    config.timestamp,
                    offset,
                    || timestamp.ok_or(Error::SynthesisError),
                )?;

                // Extract age and calculate if above 18
                let age_extractor = AgeExtractor::new(max_data_length);
                let age_data = age_extractor.extract(&mut region, &n_delimited_data, &self.delimiter_indices, &timestamp)?;

                // Assign age output
                region.assign_advice(
                    || "age_above_18",
                    config.age_above_18,
                    offset,
                    || age_data.age.ok_or(Error::SynthesisError),
                )?;

                let age_above_18 = age_data.age.map(|age| age > Value::known(F::from(18u64)));
                region.assign_advice(
                    || "age_above_18_checker",
                    config.age_above_18,
                    offset,
                    || age_above_18.ok_or(Error::SynthesisError),
                )?;

                // Extract gender
                let gender_extractor = GenderExtractor::new(max_data_length);
                let gender = gender_extractor.extract(&mut region, &age_data.n_delimited_data_shifted_to_dob)?;

                // Assign gender output
                region.assign_advice(
                    || "gender",
                    config.gender,
                    offset,
                    || gender.ok_or(Error::SynthesisError),
                )?;

                // Extract PIN code
                let pin_code_extractor = PinCodeExtractor::new(max_data_length);
                let pin_code = pin_code_extractor.extract(&mut region, &n_delimited_data, &self.delimiter_indices)?;

                // Assign pin code output
                region.assign_advice(
                    || "pin_code",
                    config.pin_code,
                    offset,
                    || pin_code.ok_or(Error::SynthesisError),
                )?;

                // Extract state
                let state_extractor = ExtractAndPackAsInt::new(max_data_length, statePosition());
                let state = state_extractor.extract(&mut region, &n_delimited_data, &self.delimiter_indices)?;

                // Assign state output
                region.assign_advice(
                    || "state",
                    config.state,
                    offset,
                    || state.ok_or(Error::SynthesisError),
                )?;

                // Extract photo
                let photo_extractor = PhotoExtractor::new(max_data_length);
                let photo = photo_extractor.extract(&mut region, &n_delimited_data, self.delimiter_indices[photoPosition() - 1], self.qr_data_padded_length)?;

                for (i, &photo_part) in photo.iter().enumerate() {
                    region.assign_advice(
                        || format!("photo_{}", i),
                        config.photo[i],
                        offset,
                        || photo_part.ok_or(Error::SynthesisError),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<F: FieldExt> QRDataExtractorCircuit<F> {
    pub fn new(
        data: Vec<Value<F>>,
        qr_data_padded_length: Value<F>,
        delimiter_indices: Vec<Value<F>>,
    ) -> Self {
        Self {
            data,
            qr_data_padded_length,
            delimiter_indices,
        }
    }
}*/
