use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
};

// Define the polynomial circuit
// out(public) = x(private)^3 + x + 5
struct CubicCircuit<F: Field> {
    pub x: Option<F>,
}

// Implement the ConstraintSynthesizer trait for the circuit
impl<F: Field> ConstraintSynthesizer<F> for CubicCircuit<F>  {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_val = self.x;
        let x = cs.new_witness_variable(|| x_val.ok_or(SynthesisError::AssignmentMissing))?;

        let x_square_val = x_val.map(|e| e.square());
        let x_square = 
            cs.new_witness_variable(|| x_square_val.ok_or(SynthesisError::AssignmentMissing))?;

        // Enforce the constraint that x * x = x_square
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + x_square)?;
        
        let x_cube_val = x_square_val.map(|mut e| {
            e.mul_assign(&x_val.unwrap());
            e
        });
        let x_cube = 
            cs.new_witness_variable(|| x_cube_val.ok_or(SynthesisError::AssignmentMissing))?;
        // Enforce the constraint that x_square * x = x_cube    
        cs.enforce_constraint(lc!() + x_square, lc!() + x, lc!() + x_cube)?;
        
        let out = cs.new_input_variable(|| {
            let mut tmp = x_cube_val.unwrap();
            tmp.add_assign(&x_val.unwrap());
            tmp.add_assign(F::from(5u32));
            Ok(tmp)
        })?;

        // Enforce the constraint that (x^3 + x + 5) * 1 = out
        cs.enforce_constraint(
            lc!() + x_cube + x + (F::from(5u32), ConstraintSystem::<F>::one()),
            lc!() + ConstraintSystem::<F>::one(),
            lc!() + out,
        )?;        

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381, Fr as BlsFr};
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use ark_std::UniformRand;

    #[test]
    fn test_groth16_cubic() {
        let mut rng = ark_std::rand::thread_rng();

        let root = BlsFr::rand(&mut rng);
        let out = root * root * root + root + BlsFr::from(5);
        
        // Generate a proving key and verification key for the circuit
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            CubicCircuit::<BlsFr> { x: None},
            &mut rng,
        ).unwrap();

        // Generate a proof of knowledge for the circuit
        let proof = Groth16::<Bls12_381>::prove(
            &pk, 
            CubicCircuit::<BlsFr> {
                x: Some(root),
            }, 
            &mut rng,
        ).unwrap();

        // Verify the proof using the verification key
        assert!(Groth16::<Bls12_381>::verify(&vk, &[out], &proof).unwrap());
        assert!(!Groth16::<Bls12_381>::verify(&vk, &[out + BlsFr::from(1)], &proof).unwrap());
    }
}