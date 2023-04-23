use crate::{
  constants::{NUM_FE_WITHOUT_IO_FOR_CRHF, NUM_HASH_BITS},
  gadgets::{
    ecc::AllocatedPoint,
    r1cs::{AllocatedR1CSInstance, AllocatedRelaxedR1CSInstance},
    utils::{
      alloc_num_equals, alloc_scalar_as_base, alloc_zero, conditionally_select_vec, le_bits_to_num,
    },
  },
  r1cs::{R1CSInstance, RelaxedR1CSInstance},
  traits::{
    circuit::StepCircuit, commitment::CommitmentTrait, Group, ROCircuitTrait, ROConstantsCircuit,
  },
  Commitment,
};
use bellperson::{
  gadgets::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    Assignment,
  },
  Circuit, ConstraintSystem, SynthesisError,
};
use ff::Field;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NovaThreeAugmentedCircuitParams {
  limb_width: usize,
  n_limbs: usize,
  is_primary_circuit: bool, // A boolean indicating if this is the primary circuit
}

#[allow(unused)]
impl NovaThreeAugmentedCircuitParams {
  pub fn new(limb_width: usize, n_limbs: usize, is_primary_circuit: bool) -> Self {
    Self {
      limb_width,
      n_limbs,
      is_primary_circuit,
    }
  }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct NovaThreeAugmentedCircuitInputs<G: Group> {
  params: G::Scalar, // Hash(Shape of u2, Gens for u2). Needed for computing the challenge.
  i: G::Base,
  z0: Vec<G::Base>,
  zi_zero: Option<Vec<G::Base>>,
  zi_one: Option<Vec<G::Base>>,
  U: Option<RelaxedR1CSInstance<G>>,
  u_zero: Option<R1CSInstance<G>>,
  u_one: Option<R1CSInstance<G>>,
  T_zero: Option<Commitment<G>>,
  T_one: Option<Commitment<G>>,
  T_two: Option<Commitment<G>>,
}

impl<G: Group> NovaThreeAugmentedCircuitInputs<G> {
  /// Create new inputs/witness for the verification circuit
  #[allow(clippy::too_many_arguments)]
  #[allow(unused)]
  pub fn new(
    params: G::Scalar,
    i: G::Base,
    z0: Vec<G::Base>,
    zi_zero: Option<Vec<G::Base>>,
    zi_one: Option<Vec<G::Base>>,
    U: Option<RelaxedR1CSInstance<G>>,
    u_zero: Option<R1CSInstance<G>>,
    u_one: Option<R1CSInstance<G>>,
    T_zero: Option<Commitment<G>>,
    T_one: Option<Commitment<G>>,
    T_two: Option<Commitment<G>>,
  ) -> Self {
    Self {
      params,
      i,
      z0,
      zi_zero,
      zi_one,
      U,
      u_zero,
      u_one,
      T_zero,
      T_one,
      T_two,
    }
  }
}

/// The augmented circuit F' in Nova that includes a step circuit F
/// and the circuit for the verifier in Nova's non-interactive folding scheme
pub struct NovaThreeAugmentedCircuit<G: Group, SC: StepCircuit<G::Base>> {
  params: NovaThreeAugmentedCircuitParams,
  ro_consts: ROConstantsCircuit<G>,
  inputs: Option<NovaThreeAugmentedCircuitInputs<G>>,
  step_circuit: SC, // The function that is applied for each step
}

impl<G: Group, SC: StepCircuit<G::Base>> NovaThreeAugmentedCircuit<G, SC> {
  #[allow(unused)]
  /// Create a new verification circuit for the input relaxed r1cs instances
  pub fn new(
    params: NovaThreeAugmentedCircuitParams,
    inputs: Option<NovaThreeAugmentedCircuitInputs<G>>,
    step_circuit: SC,
    ro_consts: ROConstantsCircuit<G>,
  ) -> Self {
    Self {
      params,
      inputs,
      step_circuit,
      ro_consts,
    }
  }

  /// Allocate all witnesses and return
  fn alloc_witness<CS: ConstraintSystem<<G as Group>::Base>>(
    &self,
    mut cs: CS,
    arity: usize,
  ) -> Result<
    (
      AllocatedNum<G::Base>,
      AllocatedNum<G::Base>,
      Vec<AllocatedNum<G::Base>>,
      Vec<AllocatedNum<G::Base>>,
      Vec<AllocatedNum<G::Base>>,
      AllocatedRelaxedR1CSInstance<G>,
      AllocatedR1CSInstance<G>,
      AllocatedR1CSInstance<G>,
      AllocatedPoint<G>,
      AllocatedPoint<G>,
      AllocatedPoint<G>,
    ),
    SynthesisError,
  > {
    // Allocate the params
    let params = alloc_scalar_as_base::<G, _>(
      cs.namespace(|| "params"),
      self.inputs.get().map_or(None, |inputs| Some(inputs.params)),
    )?;

    // Allocate i
    let i = AllocatedNum::alloc(cs.namespace(|| "i"), || Ok(self.inputs.get()?.i))?;

    // Allocate z0
    let z_0 = (0..arity)
      .map(|i| {
        AllocatedNum::alloc(cs.namespace(|| format!("z0_{i}")), || {
          Ok(self.inputs.get()?.z0[i])
        })
      })
      .collect::<Result<Vec<AllocatedNum<G::Base>>, _>>()?;

    // Allocate zi. If inputs.zi is not provided (base case) allocate default value 0
    let zero = vec![G::Base::zero(); arity];
    let z_i_zero = (0..arity)
      .map(|i| {
        AllocatedNum::alloc(cs.namespace(|| format!("zi_zero_{i}")), || {
          Ok(self.inputs.get()?.zi_zero.as_ref().unwrap_or(&zero)[i])
        })
      })
      .collect::<Result<Vec<AllocatedNum<G::Base>>, _>>()?;
    let z_i_one = (0..arity)
      .map(|i| {
        AllocatedNum::alloc(cs.namespace(|| format!("zi_one_{i}")), || {
          Ok(self.inputs.get()?.zi_one.as_ref().unwrap_or(&zero)[i])
        })
      })
      .collect::<Result<Vec<AllocatedNum<G::Base>>, _>>()?;
    println!("hey");



    // Allocate the running instance
    let U: AllocatedRelaxedR1CSInstance<G> = AllocatedRelaxedR1CSInstance::alloc(
      cs.namespace(|| "Allocate U"),
      self.inputs.get().map_or(None, |inputs| {
        inputs.U.get().map_or(None, |U| Some(U.clone()))
      }),
      self.params.limb_width,
      self.params.n_limbs,
    )?;

    // Allocate the instance to be folded in
    let u_zero = AllocatedR1CSInstance::alloc(
      cs.namespace(|| "allocate instance u_zero to fold"),
      self.inputs.get().map_or(None, |inputs| {
        inputs.u_zero.get().map_or(None, |u| Some(u.clone()))
      }),
    )?;
    let u_one = AllocatedR1CSInstance::alloc(
      cs.namespace(|| "allocate instance u_one to fold"),
      self.inputs.get().map_or(None, |inputs| {
        inputs.u_one.get().map_or(None, |u| Some(u.clone()))
      }),
    )?;


    // Allocate T
    let T_zero = AllocatedPoint::alloc(
      cs.namespace(|| "allocate T_zero"),
      self.inputs.get().map_or(None, |inputs| {
        inputs.T_zero.get().map_or(None, |T| Some(T.to_coordinates()))
      }),
    )?;
    let T_one = AllocatedPoint::alloc(
      cs.namespace(|| "allocate T_one"),
      self.inputs.get().map_or(None, |inputs| {
        inputs.T_one.get().map_or(None, |T| Some(T.to_coordinates()))
      }),
    )?;
    let T_two = AllocatedPoint::alloc(
      cs.namespace(|| "allocate T_two"),
      self.inputs.get().map_or(None, |inputs| {
        inputs.T_two.get().map_or(None, |T| Some(T.to_coordinates()))
      }),
    )?;



    Ok((params, i, z_0, z_i_zero, z_i_one, U, u_zero, u_one, T_zero, T_one, T_two))
  }

  /// Synthesizes base case and returns the new relaxed R1CSInstance
  fn synthesize_base_case<CS: ConstraintSystem<<G as Group>::Base>>(
    &self,
    mut cs: CS,
    u: AllocatedR1CSInstance<G>,
  ) -> Result<AllocatedRelaxedR1CSInstance<G>, SynthesisError> {
    let U_default: AllocatedRelaxedR1CSInstance<G> = if self.params.is_primary_circuit {
      // The primary circuit just returns the default R1CS instance
      AllocatedRelaxedR1CSInstance::default(
        cs.namespace(|| "Allocate U_default"),
        self.params.limb_width,
        self.params.n_limbs,
      )?
    } else {
      // The secondary circuit returns the incoming R1CS instance
      AllocatedRelaxedR1CSInstance::from_r1cs_instance(
        cs.namespace(|| "Allocate U_default"),
        u,
        self.params.limb_width,
        self.params.n_limbs,
      )?
    };
    Ok(U_default)
  }
  /// Synthesizes non base case and returns the new relaxed R1CSInstance
  /// And a boolean indicating if all checks pass
  #[allow(clippy::too_many_arguments)]
  fn synthesize_three_non_base_case<CS: ConstraintSystem<<G as Group>::Base>>(
    &self,
    mut cs: CS,
    params: AllocatedNum<G::Base>,
    i: AllocatedNum<G::Base>,
    z_0: Vec<AllocatedNum<G::Base>>,
    z_i: [Vec<AllocatedNum<G::Base>>; 2],
    U: AllocatedRelaxedR1CSInstance<G>,
    u: [AllocatedR1CSInstance<G>; 2],
    T: [AllocatedPoint<G>; 3],
    arity: usize,
  ) -> Result<(AllocatedRelaxedR1CSInstance<G>, AllocatedBit), SynthesisError> {
    // Check that u.x[0] = Hash(params, U, i, z0, zi)
    let mut ro = G::ROCircuit::new(
      self.ro_consts.clone(),
      NUM_FE_WITHOUT_IO_FOR_CRHF + 2 * arity,
    );
    ro.absorb(params.clone());
    ro.absorb(i);
    for e in z_0 {
      ro.absorb(e);
    }
    for z in z_i {
      for e in z { // XXX
        ro.absorb(e);
      }
    }
    U.absorb_in_ro(cs.namespace(|| "absorb U"), &mut ro)?;

    let hash_bits = ro.squeeze(cs.namespace(|| "Input hash"), NUM_HASH_BITS)?;
    let hash = le_bits_to_num(cs.namespace(|| "bits to hash"), hash_bits)?;
    let check_pass = alloc_num_equals(
      cs.namespace(|| "check consistency of u.X[0] with H(params, U, i, z0, zi)"),
      &u[0].X0,
      &hash,
    )?; // XXX

    // Run NIFS Verifier
    let U_fold = U.fold_three_with_r1cs(
      cs.namespace(|| "compute fold of U and u"),
      params,
      u[0].clone(), u[1].clone(),
      T[0].clone(), T[1].clone(), T[2].clone(), // XXX
      self.ro_consts.clone(),
      self.params.limb_width,
      self.params.n_limbs,
    )?;

    Ok((U_fold, check_pass))
  }
}

impl<G: Group, SC: StepCircuit<G::Base>> Circuit<<G as Group>::Base>
  for NovaThreeAugmentedCircuit<G, SC>
{

  fn synthesize<CS: ConstraintSystem<<G as Group>::Base>>(
    self,
    cs: &mut CS,
  ) -> Result<(), SynthesisError> {
    let arity = self.step_circuit.arity();

    // Allocate all witnesses
    let (params, i, z_0, z_i_zero, z_i_one, U, u_zero, u_one, T_zero, T_one, T_two) =
      self.alloc_witness(cs.namespace(|| "allocate the circuit witness"), arity)?;

    // Compute variable indicating if this is the base case
    let zero = alloc_zero(cs.namespace(|| "zero"))?;
    let is_base_case = alloc_num_equals(cs.namespace(|| "Check if base case"), &i.clone(), &zero)?;

    // Synthesize the circuit for the base case and get the new running instance
    let Unew_base = self.synthesize_base_case(cs.namespace(|| "base case"), u_one.clone())?; // ????

    // Gets new runnning instance

    // Synthesize the circuit for the non-base case and get the new running
    // instance along with a boolean indicating if all checks have passed
    let (Unew_non_base, check_non_base_pass) = self.synthesize_three_non_base_case(
      cs.namespace(|| "synthesize non base case"),
      params.clone(),
      i.clone(),
      z_0.clone(),
      [z_i_zero.clone(), z_i_one.clone()],
      U,
      [u_zero.clone(), u_one.clone()],
      [T_zero, T_one, T_two,],
      arity,
    )?;

    // Either check_non_base_pass=true or we are in the base case
    let should_be_false = AllocatedBit::nor(
      cs.namespace(|| "check_non_base_pass nor base_case"),
      &check_non_base_pass,
      &is_base_case,
    )?;
    cs.enforce(
      || "check_non_base_pass nor base_case = false",
      |lc| lc + should_be_false.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc,
    );

    // Compute the U_new
    let Unew = Unew_base.conditionally_select(
      cs.namespace(|| "compute U_new"),
      Unew_non_base,
      &Boolean::from(is_base_case.clone()),
    )?;

    // Compute i + 1
    let i_new = AllocatedNum::alloc(cs.namespace(|| "i + 1"), || {
      Ok(*i.get_value().get()? + G::Base::one())
    })?;
    cs.enforce(
      || "check i + 1",
      |lc| lc,
      |lc| lc,
      |lc| lc + i_new.get_variable() - CS::one() - i.get_variable(),
    );

    // Compute z_{i+1}
    let z_input = conditionally_select_vec(
      cs.namespace(|| "select input to F"),
      &z_0,
      &z_i_one,
      &Boolean::from(is_base_case),
    )?;

    let z_next = self
      .step_circuit
      .synthesize(&mut cs.namespace(|| "F"), &z_input)?;

    if z_next.len() != arity {
      return Err(SynthesisError::IncompatibleLengthVector(
        "z_next".to_string(),
      ));
    }

    // Compute the new hash H(params, Unew, i+1, z0, z_{i+1})
    let mut ro = G::ROCircuit::new(self.ro_consts, NUM_FE_WITHOUT_IO_FOR_CRHF + 2 * arity);
    ro.absorb(params);
    ro.absorb(i_new.clone());
    for e in z_0 {
      ro.absorb(e);
    }
    for e in z_next {
      ro.absorb(e);
    }
    Unew.absorb_in_ro(cs.namespace(|| "absorb U_new"), &mut ro)?;
    let hash_bits = ro.squeeze(cs.namespace(|| "output hash bits"), NUM_HASH_BITS)?;
    let hash = le_bits_to_num(cs.namespace(|| "convert hash to num"), hash_bits)?;

    // Outputs the computed hash and u.X[1] that corresponds to the hash of the other circuit
    u_one.X1
      .inputize(cs.namespace(|| "Output unmodified hash of the other circuit"))?;
    hash.inputize(cs.namespace(|| "output new hash of this circuit"))?;

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bellperson::{shape_cs::ShapeCS, solver::SatisfyingAssignment};
  type G1 = pasta_curves::pallas::Point;
  type G2 = pasta_curves::vesta::Point;

  use crate::constants::{BN_LIMB_WIDTH, BN_N_LIMBS};
  use crate::{
    bellperson::r1cs::{NovaShape, NovaWitness},
    provider::poseidon::PoseidonConstantsCircuit,
    traits::{circuit::TrivialTestCircuit, ROConstantsTrait},
  };

  #[test]
  fn test_recursive_circuit() {
    // In the following we use 1 to refer to the primary, and 2 to refer to the secondary circuit
    let params1 = NovaThreeAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, true);
    let params2 = NovaThreeAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, false);
    let ro_consts1: ROConstantsCircuit<G2> = PoseidonConstantsCircuit::new();
    let ro_consts2: ROConstantsCircuit<G1> = PoseidonConstantsCircuit::new();

    // Initialize the shape and ck for the primary
    let circuit1: NovaThreeAugmentedCircuit<G2, TrivialTestCircuit<<G2 as Group>::Base>> =
      NovaThreeAugmentedCircuit::new(
        params1.clone(),
        None,
        TrivialTestCircuit::default(),
        ro_consts1.clone(),
      );
    let mut cs: ShapeCS<G1> = ShapeCS::new();
    let _ = circuit1.synthesize(&mut cs);
    let (shape1, ck1) = cs.r1cs_shape();
    assert_eq!(cs.num_constraints(), 9815);

    // Initialize the shape and ck for the secondary
    let circuit2: NovaThreeAugmentedCircuit<G1, TrivialTestCircuit<<G1 as Group>::Base>> =
      NovaThreeAugmentedCircuit::new(
        params2.clone(),
        None,
        TrivialTestCircuit::default(),
        ro_consts2.clone(),
      );
    let mut cs: ShapeCS<G2> = ShapeCS::new();
    let _ = circuit2.synthesize(&mut cs);
    let (shape2, ck2) = cs.r1cs_shape();
    assert_eq!(cs.num_constraints(), 10347);

    // Execute the base case for the primary
    let zero1 = <<G2 as Group>::Base as Field>::zero();
    let mut cs1: SatisfyingAssignment<G1> = SatisfyingAssignment::new();
    let inputs1: NovaThreeAugmentedCircuitInputs<G2> = NovaThreeAugmentedCircuitInputs::new(
      shape2.get_digest(),
      zero1,
      vec![zero1],
      None,
      None,
      None,
      None,
      None,
      None,
      None,
      None,
    );
    let circuit1: NovaThreeAugmentedCircuit<G2, TrivialTestCircuit<<G2 as Group>::Base>> =
      NovaThreeAugmentedCircuit::new(
        params1,
        Some(inputs1),
        TrivialTestCircuit::default(),
        ro_consts1,
      );
    let _ = circuit1.synthesize(&mut cs1);
    let (inst1, witness1) = cs1.r1cs_instance_and_witness(&shape1, &ck1).unwrap();
    // Make sure that this is satisfiable
    assert!(shape1.is_sat(&ck1, &inst1, &witness1).is_ok());

    // Execute the base case for the secondary
    let zero2 = <<G1 as Group>::Base as Field>::zero();
    let mut cs2: SatisfyingAssignment<G2> = SatisfyingAssignment::new();
    let inputs2: NovaThreeAugmentedCircuitInputs<G1> = NovaThreeAugmentedCircuitInputs::new(
      shape1.get_digest(),
      zero2,
      vec![zero2],
      None,
      None,
      None,
      None,
      Some(inst1),
      None,
      None,
      None,
    );
    let circuit: NovaThreeAugmentedCircuit<G1, TrivialTestCircuit<<G1 as Group>::Base>> =
      NovaThreeAugmentedCircuit::new(
        params2,
        Some(inputs2),
        TrivialTestCircuit::default(),
        ro_consts2,
      );
    let _ = circuit.synthesize(&mut cs2);
    let (inst2, witness2) = cs2.r1cs_instance_and_witness(&shape2, &ck2).unwrap();
    // Make sure that it is satisfiable
    assert!(shape2.is_sat(&ck2, &inst2, &witness2).is_ok());
  }
}
