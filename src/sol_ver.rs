use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves as halo2_curves;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};
use rand::rngs::OsRng;
use snark_verifier_sdk::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk};
use snark_verifier_sdk::halo2::gen_srs;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};
use snark_verifier_sdk::{CircuitExt, SHPLONK};
use std::path::Path;

fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
    let circuit = application::StandardPlonk::rand(OsRng);

    let pk = gen_pk(params, &circuit, Some(Path::new("./examples/app.pk")));
    gen_snark_shplonk(params, &pk, circuit, None::<&str>)
}

fn main() {
    let params_app = gen_srs(8);
    let snarks = [(); 3].map(|_| gen_application_snark(&params_app));

    let params = gen_srs(22);
    let agg_circuit = AggregationCircuit::<SHPLONK>::new(&params, snarks);

    let start0 = start_timer!(|| "gen vk & pk");
    let pk = gen_pk(
        &params,
        &agg_circuit.without_witnesses(),
        Some(Path::new("./examples/agg.pk")),
    );
    end_timer!(start0);

    let num_instances = agg_circuit.num_instance();
    let instances = agg_circuit.instances();
    let proof_calldata = gen_evm_proof_shplonk(&params, &pk, agg_circuit, instances.clone());

    let deployment_code = gen_evm_verifier_shplonk::<AggregationCircuit<SHPLONK>>(
        &params,
        pk.get_vk(),
        num_instances,
        Some(Path::new("./examples/StandardPlonkVerifierExample.sol")),
    );
    evm_verify(deployment_code, instances, proof_calldata);
}