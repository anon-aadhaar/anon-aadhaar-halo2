use halo2_base::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
    poly::Rotation,
};
use ff::PrimeField;

#[derive(Clone, Debug)]
struct RevealConfig {
    advice: [Column<Advice>; 8],
    instance: [Column<Instance>; 4],
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
            instance,
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
                
                region.assign_advice(
                    || format!("{}_constraint", i),
                    config.advice[0],
                    1,
                    || reveal_age_above_18 * (reveal_age_above_18 - F::one())
                )?;
                
                region.assign_advice(
                    || format!("{}_constraint", i),
                    config.advice[1],
                    1,
                    || reveal_gender * (reveal_gender - F::one())
                )?;

                region.assign_advice(
                    || format!("{}_constraint", i),
                    config.advice[2],
                    1,
                    || reveal_pin_code * (reveal_pin_code - F::one())
                )?;

                region.assign_advice(
                    || format!("{}_constraint", i),
                    config.advice[3],
                    1,
                    || reveal_state * (reveal_state - F::one())
                )?;

                Ok(())
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_base::{
        arithmetic::FieldExt,
        dev::MockProver,
        pasta::Fp,
    };

    #[test]
    fn test_reveal_circuit() {
        let reveal_circuit = RevealCircuit {
            reveal_age_above_18: Value::known(Fp::from(1)),
            reveal_gender: Value::known(Fp::from(1)),
            reveal_pin_code: Value::known(Fp::from(1)),
            reveal_state: Value::known(Fp::from(1)),
            age_above_18: Value::known(Fp::from(1)),
            gender: Value::known(Fp::from(1)),
            pin_code: Value::known(Fp::from(1)),
            state: Value::known(Fp::from(1)),
        };

        let prover = MockProver::run(9, &reveal_circuit, vec![vec![Fp::from(1), Fp::from(1), Fp::from(1), Fp::from(1)]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
