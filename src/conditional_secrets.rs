use halo2_base::halo2_proofs::arithmetic::FieldExt;
use halo2_base::halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector, Expression};
use halo2_base::halo2_proofs::poly::Rotation;
use halo2_base::halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};

#[derive(Default)]
struct IdentityCircuit {
    reveal_age_above_18: Option<bool>,
    age_above_18: Option<u8>,
    qr_data_age_above_18: Option<u8>,
    reveal_gender: Option<bool>,
    gender: Option<u8>,
    qr_data_gender: Option<u8>,
    reveal_pincode: Option<bool>, 
    pincode: Option<u32>,
    qr_data_pincode: Option<u32>,
    reveal_state: Option<bool>,
    state: Option<u8>,
    qr_data_state: Option<u8>,
}

#[derive(Clone)]
struct IdentityConfig {
    reveal_age_above_18: Column<Advice>,
    age_above_18: Column<Advice>,
    qr_data_age_above_18: Column<Advice>,
    reveal_gender: Column<Advice>,
    gender: Column<Advice>,
    qr_data_gender: Column<Advice>,
    reveal_pincode: Column<Advice>,
    pincode: Column<Advice>,
    qr_data_pincode: Column<Advice>,
    reveal_state: Column<Advice>,
    state: Column<Advice>,
    qr_data_state: Column<Advice>,
    s: Selector,
}

impl<F: FieldExt> Circuit<F> for IdentityCircuit {
    type Config = IdentityConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let reveal_age_above_18 = meta.advice_column();
        let age_above_18 = meta.advice_column();
        let qr_data_age_above_18 = meta.advice_column();
        let reveal_gender = meta.advice_column();
        let gender = meta.advice_column();
        let qr_data_gender = meta.advice_column();
        let reveal_pincode = meta.advice_column();
        let pincode = meta.advice_column();
        let qr_data_pincode = meta.advice_column();
        let reveal_state = meta.advice_column();
        let state = meta.advice_column();
        let qr_data_state = meta.advice_column();
        let s = meta.selector();

        meta.create_gate("revealAgeAbove18 constraint", |meta| {
            let s = meta.query_selector(s);
            let reveal_age_above_18 = meta.query_advice(reveal_age_above_18, Rotation::cur());
            vec![s * reveal_age_above_18.clone() * (reveal_age_above_18 - Expression::Constant(F::one()))]
        });

        meta.create_gate("ageAbove18 assignment", |meta| {
            let s = meta.query_selector(s);
            let reveal_age_above_18 = meta.query_advice(reveal_age_above_18, Rotation::cur());
            let age_above_18 = meta.query_advice(age_above_18, Rotation::cur());
            let qr_data_age_above_18 = meta.query_advice(qr_data_age_above_18, Rotation::cur());
            vec![
                s * (age_above_18 - reveal_age_above_18 * qr_data_age_above_18)
            ]
        });

        meta.create_gate("gender constraint", |meta| {
            let s = meta.query_selector(s);
            let reveal_gender = meta.query_advice(reveal_gender, Rotation::cur());
            vec![s * reveal_gender.clone() * (reveal_gender - Expression::Constant(F::one()))]
        });

        meta.create_gate("gender assignment", |meta| {
            let s = meta.query_selector(s);
            let gender = meta.query_advice(gender, Rotation::cur());
            let qr_data_gender = meta.query_advice(qr_data_gender, Rotation::cur());
            vec![
                s * (gender - qr_data_gender)
            ]
        });

        meta.create_gate("pincode constraint", |meta| {
            let s = meta.query_selector(s);
            let reveal_pincode = meta.query_advice(reveal_pincode, Rotation::cur());
            vec![s * reveal_pincode.clone() * (reveal_pincode - Expression::Constant(F::one()))]
        });

        meta.create_gate("pincode assignment", |meta| {
            let s = meta.query_selector(s);
            let pincode = meta.query_advice(pincode, Rotation::cur());
            let qr_data_pincode = meta.query_advice(qr_data_pincode, Rotation::cur());
            vec![
                s * (pincode - qr_data_pincode)
            ]
        });

        meta.create_gate("state constraint", |meta| {
            let s = meta.query_selector(s);
            let reveal_state = meta.query_advice(reveal_state, Rotation::cur());
            vec![s * reveal_state.clone() * (reveal_state - Expression::Constant(F::one()))]
        });

        meta.create_gate("state assignment", |meta| {
            let s = meta.query_selector(s);
            let state = meta.query_advice(state, Rotation::cur());
            let qr_data_state = meta.query_advice(qr_data_state, Rotation::cur());
            vec![
                s * (state - qr_data_state)
            ]
        });

        IdentityConfig {
            reveal_age_above_18,
            age_above_18,
            qr_data_age_above_18,
            reveal_gender,
            gender,
            qr_data_gender,
            reveal_pincode,
            pincode,
            qr_data_pincode,
            reveal_state,
            state,
            qr_data_state,
            s,
        }
    }

    fn synthesize(&self, config: IdentityConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "identity constraints",
            |mut region| {
                config.s.enable(&mut region, 0)?;

                region.assign_advice(
                    || "reveal_age_above_18",
                    config.reveal_age_above_18,
                    0,
                    || Value::known(F::from(self.reveal_age_above_18.unwrap_or(false) as u64))
                )?;

                region.assign_advice(
                    || "qr_data_age_above_18",
                    config.qr_data_age_above_18,
                    0,
                    || Value::known(F::from(self.qr_data_age_above_18.unwrap_or(0) as u64))
                )?;

                region.assign_advice(
                    || "age_above_18",
                    config.age_above_18,
                    0,
                    || Value::known(F::from(self.age_above_18.unwrap_or(0) as u64))
                )?;

                region.assign_advice(
                    || "reveal_gender",
                    config.reveal_gender,
                    0,
                    || Value::known(F::from(self.reveal_gender.unwrap_or(false) as u64))
                )?;

                region.assign_advice(
                    || "gender",
                    config.gender,
                    0,
                    || Value::known(F::from(self.gender.unwrap_or(0) as u64))
                )?;

                region.assign_advice(
                    || "qr_data_gender",
                    config.qr_data_gender,
                    0,
                    || Value::known(F::from(self.qr_data_gender.unwrap_or(0) as u64))
                )?;

                region.assign_advice(
                    || "reveal_pincode",
                    config.reveal_pincode,
                    0,
                    || Value::known(F::from(self.reveal_pincode.unwrap_or(false) as u64))
                )?;

                region.assign_advice(
                    || "pincode",
                    config.pincode,
                    0,
                    || Value::known(F::from(self.pincode.unwrap_or(0) as u64))
                )?;

                region.assign_advice(
                    || "qr_data_pincode",
                    config.qr_data_pincode,
                    0,
                    || Value::known(F::from(self.qr_data_pincode.unwrap_or(0) as u64))
                )?;

                region.assign_advice(
                    || "reveal_state",
                    config.reveal_state,
                    0,
                    || Value::known(F::from(self.reveal_state.unwrap_or(false) as u64))
                )?;

                region.assign_advice(
                    || "state",
                    config.state,
                    0,
                    || Value::known(F::from(self.state.unwrap_or(0) as u64))
                )?;

                region.assign_advice(
                    || "qr_data_state",
                    config.qr_data_state,
                    0,
                    || Value::known(F::from(self.qr_data_state.unwrap_or(0) as u64))
                )?;

                Ok(())
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::pasta::Fp};

    #[test]
    fn test_identity_circuit() {
        let k = 4; // The size of the circuit (log_2 of the number of rows)

        // Test case where reveal_age_above_18 is true
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(1),
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(1),
            qr_data_gender: Some(1),
            reveal_pincode: Some(true),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(1),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // Test case where reveal_age_above_18 is false
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(false),
            age_above_18: Some(0),
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(1),
            qr_data_gender: Some(1),
            reveal_pincode: Some(true),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(1),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // Test case where the constraint should fail due to age_above_18 
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(0), // This should fail because age_above_18 should be 1
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(1),
            qr_data_gender: Some(1),
            reveal_pincode: Some(true),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(1),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());

        // Test case where the constraint should fail due to gender
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(1), 
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(0), // This should fail because gender should be 1
            qr_data_gender: Some(1),
            reveal_pincode: Some(true),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(1),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());

        // Test case where the constraint should fail due to pincode
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(1), 
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(1), 
            qr_data_gender: Some(1),
            reveal_pincode: Some(true),
            pincode: Some(654321), // This should fail because pincode should be 123456
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(4),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());

        // Test case where the constraint should fail due to state
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(1), 
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(1), 
            qr_data_gender: Some(1),
            reveal_pincode: Some(true),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(4), // This should fail because state should be 1
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());

        // Test case where the reveal_gender is false
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(1), 
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(false),
            gender: Some(1), 
            qr_data_gender: Some(1),
            reveal_pincode: Some(false),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(1),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_ok());

        // Test case where the reveal_pincode is false
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(1), 
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(1), 
            qr_data_gender: Some(1),
            reveal_pincode: Some(false),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(true),
            state: Some(1),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_ok());

        // Test case where the reveal_state is false
        let circuit = IdentityCircuit {
            reveal_age_above_18: Some(true),
            age_above_18: Some(1), 
            qr_data_age_above_18: Some(1),
            reveal_gender: Some(true),
            gender: Some(1), 
            qr_data_gender: Some(1),
            reveal_pincode: Some(false),
            pincode: Some(123456),
            qr_data_pincode: Some(123456),
            reveal_state: Some(false),
            state: Some(1),
            qr_data_state: Some(1),
        };

        let prover: MockProver<Fp> = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}

