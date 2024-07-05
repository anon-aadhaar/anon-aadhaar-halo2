use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Column, Advice, Selector},
};

#[derive(Clone, Debug)]
struct RevealConfig {
    advice: [Column<Advice>; 4],
    selector: Selector,
}

struct RevealCircuit<F: FieldExt> {
    reveal_age_above_18: Value<F>,
    reveal_gender: Value<F>,
    reveal_pin_code: Value<F>,
    reveal_state: Value<F>,
}

impl<F: FieldExt> Circuit<F> for RevealCircuit<F> {
    type Config = RevealConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
        ];
        let selector = cs.selector();

        for &column in advice.iter() {
            cs.enable_equality(column);
        }

        RevealConfig { advice, selector }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let reveal_age_above_18 = self.reveal_age_above_18;
                let reveal_gender = self.reveal_gender;
                let reveal_pin_code = self.reveal_pin_code;
                let reveal_state = self.reveal_state;

                region.assign_advice(
                    || "reveal_age_above_18",
                    config.advice[0],
                    0,
                    || reveal_age_above_18,
                )?;
                region.assign_advice(
                    || "reveal_gender",
                    config.advice[1],
                    0,
                    || reveal_gender,
                )?;
                region.assign_advice(
                    || "reveal_pin_code",
                    config.advice[2],
                    0,
                    || reveal_pin_code,
                )?;
                region.assign_advice(
                    || "reveal_state",
                    config.advice[3],
                    0,
                    || reveal_state,
                )?;

                // Constraints: reveal * (reveal - 1) == 0
                region.assign_advice(
                    || "reveal_age_above_18 constraint",
                    config.advice[0],
                    1,
                    || reveal_age_above_18.map(|v| v * (v - F::one())),
                )?;
                region.assign_advice(
                    || "reveal_gender constraint",
                    config.advice[1],
                    1,
                    || reveal_gender.map(|v| v * (v - F::one())),
                )?;
                region.assign_advice(
                    || "reveal_pin_code constraint",
                    config.advice[2],
                    1,
                    || reveal_pin_code.map(|v| v * (v - F::one())),
                )?;
                region.assign_advice(
                    || "reveal_state constraint",
                    config.advice[3],
                    1,
                    || reveal_state.map(|v| v * (v - F::one())),
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::{
        dev::MockProver,
        halo2curves::pasta::Fp,
    };

    #[test]
    fn test_reveal_circuit() {
        let k = 4; // Security parameter

        let reveal_age_above_18 = Fp::from(1); // Valid: 0 or 1
        let reveal_gender = Fp::from(0);       // Valid: 0 or 1
        let reveal_pin_code = Fp::from(1);     // Valid: 0 or 1
        let reveal_state = Fp::from(0);        // Valid: 0 or 1

        let circuit = RevealCircuit {
            reveal_age_above_18: Value::known(reveal_age_above_18),
            reveal_gender: Value::known(reveal_gender),
            reveal_pin_code: Value::known(reveal_pin_code),
            reveal_state: Value::known(reveal_state),
        };

        let public_inputs = vec![];

        // Create a mock prover
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.verify().unwrap();
    }

    #[test]
    fn test_reveal_circuit_invalid() {
        let k = 4; // Security parameter

        let reveal_age_above_18 = Fp::from(2); // Invalid: not 0 or 1
        let reveal_gender = Fp::from(3);       // Invalid: not 0 or 1
        let reveal_pin_code = Fp::from(1);     // Valid: 0 or 1
        let reveal_state = Fp::from(0);        // Valid: 0 or 1

        let circuit = RevealCircuit {
            reveal_age_above_18: Value::known(reveal_age_above_18),
            reveal_gender: Value::known(reveal_gender),
            reveal_pin_code: Value::known(reveal_pin_code),
            reveal_state: Value::known(reveal_state),
        };

        let public_inputs = vec![];

        // Create a mock prover
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        assert!(prover.verify().is_err());
    }
}

/*use halo2_base::halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Column, Advice, Selector},
};

#[derive(Clone, Debug)]
struct RevealConfig {
    advice: [Column<Advice>; 8],
    //instance: [Column<Instance>; 4],
    selector: Selector,
}

struct RevealCircuit<F: FieldExt> {
    reveal_age_above_18: Value<F>,
    reveal_gender: Value<F>,
    reveal_pin_code: Value<F>,
    reveal_state: Value<F>,
    age_above_18: Value<F>,
    gender: Value<F>,
    pin_code: Value<F>,
    state: Value<F>,
}

impl<F: FieldExt> Circuit<F> for RevealCircuit<F> {
    type Config = RevealConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!();
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
            cs.advice_column(),
        ];
        let instance = [
            cs.instance_column(),
            cs.instance_column(),
            cs.instance_column(),
            cs.instance_column(),
        ];
        let selector = cs.selector();

        cs.enable_equality(advice[0]);
        cs.enable_equality(advice[1]);
        cs.enable_equality(advice[2]);
        cs.enable_equality(advice[3]);
        cs.enable_equality(advice[4]);
        cs.enable_equality(advice[5]);
        cs.enable_equality(advice[6]);
        cs.enable_equality(advice[7]);

        cs.enable_equality(instance[0]);
        cs.enable_equality(instance[1]);
        cs.enable_equality(instance[2]);
        cs.enable_equality(instance[3]);

        RevealConfig {
            advice,
            //instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let reveal_age_above_18 = self.reveal_age_above_18;
                let reveal_gender = self.reveal_gender;
                let reveal_pin_code = self.reveal_pin_code;
                let reveal_state = self.reveal_state;

                let age_above_18 = self.age_above_18;
                let gender = self.gender;
                let pin_code = self.pin_code;
                let state = self.state;

                region.assign_advice(|| "reveal_age_above_18", config.advice[0], 0, || reveal_age_above_18)?;
                region.assign_advice(|| "reveal_gender", config.advice[1], 0, || reveal_gender)?;
                region.assign_advice(|| "reveal_pin_code", config.advice[2], 0, || reveal_pin_code)?;
                region.assign_advice(|| "reveal_state", config.advice[3], 0, || reveal_state)?;

                region.assign_advice(|| "age_above_18", config.advice[4], 0, || age_above_18)?;
                region.assign_advice(|| "gender", config.advice[5], 0, || gender)?;
                region.assign_advice(|| "pin_code", config.advice[6], 0, || pin_code)?;
                region.assign_advice(|| "state", config.advice[7], 0, || state)?;

                let one = F::one();
                let reveal_age_above_18_field = self.reveal_age_above_18.to_field();
                let reveal_gender_field = self.reveal_gender.to_field();
                let reveal_pin_code_field = self.reveal_pin_code.to_field();
                let reveal_state_field = self.reveal_state.to_field();

                region.assign_advice(
                    || format!("{}_constraint", 0),
                    config.advice[0],
                    1,
                    || reveal_age_above_18_field * (reveal_age_above_18_field - one.clone())
                )?;
                
                region.assign_advice(
                    || format!("{}_constraint", 1),
                    config.advice[1],
                    1,
                    || reveal_gender_field.clone() * (reveal_gender_field - one.clone())
                )?;

                region.assign_advice(
                    || format!("{}_constraint", 2),
                    config.advice[2],
                    1,
                    || reveal_pin_code_field.clone() * (reveal_pin_code_field - one.clone())
                )?;

                region.assign_advice(
                    || format!("{}_constraint", 3),
                    config.advice[3],
                    1,
                    || reveal_state_field * (reveal_state_field - one)
                )?;

                Ok(())
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::halo2_proofs::{
        dev::MockProver,
        halo2curves::pasta::Fp,
    };

    #[test]
    fn test_reveal_circuit() {
        let k = 4; // Security parameter
        let reveal_age_above_18 = Fp::from(25u64); // Sample values
        let reveal_gender = Fp::from(1u64);
        let reveal_pin_code = Fp::from(1234u64);
        let reveal_state = Fp::from(10u64);
        let age_above_18 = Fp::from(1u64);
        let gender = Fp::from(0u64);
        let pin_code = Fp::from(5678u64);
        let state = Fp::from(5u64);

        let circuit = RevealCircuit {
            reveal_age_above_18: Value::known(reveal_age_above_18),
            reveal_gender: Value::known(reveal_gender),
            reveal_pin_code: Value::known(reveal_pin_code),
            reveal_state: Value::known(reveal_state),
            age_above_18: Value::known(age_above_18),
            gender: Value::known(gender),
            pin_code: Value::known(pin_code),
            state: Value::known(state),
        };

        // Prepare public inputs (if any)
        //let public_inputs = vec![reveal_age_above_18, reveal_gender, reveal_pin_code, reveal_state];
        let public_inputs = vec![];

        // Create a mock prover
        let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
        prover.verify().unwrap();
    }
}*/
