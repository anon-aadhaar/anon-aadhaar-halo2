use halo2_base::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
struct SquareConfig {
    advice: [Column<Advice>; 2],
    instance: Column<Instance>,
    selector: Selector,
}

struct SquareCircuit<F: FieldExt> {
    signal_hash: Value<F>,
}

impl<F: FieldExt> Circuit<F> for SquareCircuit<F> {
    type Config = SquareConfig;

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [cs.advice_column(), cs.advice_column()];
        let instance = cs.instance_column();
        let selector = cs.selector();

        cs.enable_equality(advice[0]);
        cs.enable_equality(advice[1]);
        cs.enable_equality(instance);

        cs.create_gate("square", |meta| {
            let s = meta.query_selector(selector);
            let signal_hash = meta.query_advice(advice[0], Rotation::cur());
            let signal_hash_square = meta.query_advice(advice[1], Rotation::cur());

            vec![s * (signal_hash_square - signal_hash.clone() * signal_hash)]
        });

        SquareConfig {
            advice,
            instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: SquareConfig,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "square region",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let signal_hash = region.assign_advice(
                    || "signal hash",
                    config.advice[0],
                    0,
                    || self.signal_hash,
                )?;

                let signal_hash_square = region.assign_advice(
                    || "signal hash square",
                    config.advice[1],
                    0,
                    || self.signal_hash.map(|v| v * v),
                )?;

                region.constrain_equal(signal_hash_square.cell(), config.instance)?;

                Ok(())
            },
        )
    }
}

fn main() {
    let k = 4;
    let signal_hash = Some(5);

    let circuit = SquareCircuit {
        signal_hash: Value::known(signal_hash.into()),
    };

    let public_inputs = vec![signal_hash.map(|v| v * v).into()];

    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    prover.assert_satisfied();
}