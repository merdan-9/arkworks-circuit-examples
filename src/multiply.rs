use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

// Define the multiplication circuit
// c(public) = a(private) * b(private)
#[derive(Clone, Copy)]
struct MultiplyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

// Implement the ConstraintSynthesizer trait for the circuit
impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MultiplyCircuit<ConstraintF> {
    fn generate_constraints(
        self, 
        cs: ConstraintSystemRef<ConstraintF>
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            a.mul_assign(&b);
            Ok(a)
        })?;
        // Enforce the constraint that a * b = c
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr as BlsFr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::{ops::*, UniformRand};

    #[test]
    fn test_groth16_multiply() {
        let mut rng = ark_std::rand::thread_rng();

        // Generate a proving key and verification key for the circuit
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            MultiplyCircuit::<BlsFr> {
                a: None,
                b: None,
            }, 
            &mut rng,
        ).unwrap();

        for _ in 0..10 {
            // Generate random values for a and b
            let a = BlsFr::rand(&mut rng);
            let b = BlsFr::rand(&mut rng);
            let mut c = a;
            c.mul_assign(&b);

            // Generate a proof of knowledge for the circuit
            let proof = Groth16::<Bls12_381>::prove(
                &pk, 
                MultiplyCircuit {
                    a: Some(a),
                    b: Some(b),
                }, 
                &mut rng
            ).unwrap();

            // Verify the proof using the verification key
            assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());
            assert!(!Groth16::<Bls12_381>::verify(&vk, &[a], &proof).unwrap());
        }
    }
}