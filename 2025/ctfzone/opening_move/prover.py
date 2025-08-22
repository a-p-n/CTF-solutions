# This file contains the prover and verifier for the complete zero-knowledge proof protocol
#
# This implements a modern zero-knowledge proof system that combines multiple techniques:
# 1. Sumcheck Protocol: Proves circuit satisfiability by reducing polynomial evaluation to a single point
# 2. Gemini Protocol: Efficient multilinear polynomial commitment scheme
# 3. Shplonk Protocol: Batched polynomial opening for multiple polynomials
# 4. KZG Commitments: Polynomial commitment scheme for individual polynomials
#
# Protocol Overview:
# Round 0: Send verification key (circuit structure and selector polynomials)
# Round 1: Send initial witness commitments (witness polynomials)
# Round 2: Generate and send permutation polynomial commitment
# Round 3: Execute sumcheck protocol to prove constraint satisfaction
# Round 4: Prove polynomial evaluations using Gemini protocol
# Round 5: Batch verify all polynomial openings using Shplonk protocol
#
# The protocol ensures that:
# - All arithmetic constraints are satisfied
# - All permutation constraints are satisfied
# - All polynomial evaluations are consistent with commitments
from instance import (
    Instance,
    NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS,
    NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS,
)
from circuit import CircuitBuilder
from polynomial import evaluate_polynomial
from proof_polynomials import DERIVED_POLYNOMIALS, NUMBER_OF_POLYNOMIALS
from relations import RelationChallenges
from transcript import ProverTranscript, VerifierTranscript, map_tuple_from_int_to_Fq
from ff import Fr, Fq
from kzg import KZG
from gemini import GeminiProver, GeminiVerifier
import unittest
from sumcheck import SumcheckProver, SumcheckVerifier, SumcheckChallenges
from shplonk import ShplonkProver, ShplonkVerifier
from ff_ct import Fr_ct


class Prover:
    """
    The main prover class that generates proofs for the circuit satisfiability.

    The prover takes a circuit description and generates a proof that convinces
    the verifier that there exists a valid witness satisfying all circuit constraints,
    without revealing the actual witness values.

    The proof generation follows a structured protocol with multiple rounds:
    - Commitment phase: Commit to circuit polynomials and witness values
    - Sumcheck phase: Prove that all constraints are satisfied
    - Opening phase: Prove that polynomial evaluations are consistent with commitments

    Key components:
    - Instance: Contains all circuit polynomials and witness data
    - KZG: Polynomial commitment scheme for individual polynomials
    - Transcript: Communication channel with the verifier
    """

    def __init__(self, cb: CircuitBuilder):
        """
        Initialize the prover with a circuit description.

        Args:
            cb: CircuitBuilder containing the arithmetic circuit description
        """
        # Create the circuit instance with all polynomial data
        self.instance = Instance(cb)
        # Initialize the polynomial commitment scheme
        self.kzg = KZG()
        # Initialize the communication transcript with the verifier
        self.transcript = ProverTranscript()

    def generate_verification_key(self):
        """
        Generate the verification key for the circuit.

        The verification key contains commitments to the circuit structure polynomials
        that are independent of the specific witness. This allows the verifier to
        check proofs for any valid witness without needing the full circuit description.

        The verification key includes:
        - Instance size (number of gates)
        - Commitments to selector polynomials (q_m, q_l, q_r, q_o, q_c)
        - Commitments to identity polynomials (id_l, id_r, id_o)
        - Commitments to permuted identity polynomials (sigma_l, sigma_r, sigma_o)
        - Commitments to Lagrange polynomials (lagrange_first, lagrange_last)

        Returns:
            bytes: Serialized verification key that can be shared with verifiers
        """
        # Start a fresh transcript for the verification key
        self.transcript = ProverTranscript()

        # Send the instance size (number of gates in the circuit)
        self.transcript.send_to_verifier(self.instance.instance_size)

        # Send commitments to all verification key polynomials
        # These are the circuit structure polynomials that don't depend on the witness
        for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
            self.transcript.send_to_verifier(
                map_tuple_from_int_to_Fq(
                    self.kzg.commit(self.instance.all_polynomials[i])
                )
            )

        # Export the verification key as bytes
        vk = self.transcript.export_proof()

        # Reset the transcript for the actual proof
        self.transcript = ProverTranscript()
        return vk

    def prove(self, before_sumcheck_update=lambda x: None):
        """
        Generate a complete zero-knowledge proof for circuit satisfiability.

        This method executes the full proof protocol in multiple rounds:

        Round 0: Send verification key (circuit structure)
        Round 1: Send witness commitments (actual witness values)
        Round 2: Generate and send permutation polynomial
        Round 3: Execute sumcheck protocol (prove constraints are satisfied)
        Round 4: Prove polynomial evaluations using Gemini
        Round 5: Batch verify openings using Shplonk

        The proof ensures that:
        - All arithmetic constraints are satisfied (sumcheck)
        - All permutation constraints are satisfied (permutation polynomial)
        - All polynomial evaluations are consistent with commitments (Gemini + Shplonk)

        Args:
            before_sumcheck_update: Optional callback function called before sumcheck
                                   (used for testing or debugging purposes)
        """
        # Round 0: Send verification key
        # This includes the circuit structure that doesn't depend on the witness
        self.transcript.send_to_verifier(self.instance.instance_size)
        for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
            self.transcript.send_to_verifier(
                map_tuple_from_int_to_Fq(
                    self.kzg.commit(self.instance.all_polynomials[i])
                )
            )

        # Round 1: Send witness commitments
        # These are the actual witness values that prove circuit satisfiability
        for i in range(
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS,
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS
            + NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS,
        ):
            self.transcript.send_to_verifier(
                map_tuple_from_int_to_Fq(
                    self.kzg.commit(self.instance.all_polynomials[i])
                )
            )

        # Get challenges for permutation polynomial generation
        # These ensure the permutation polynomial is unique to this proof
        beta_challenge = self.transcript.get_challenge()
        self.beta_challenge = beta_challenge
        gamma_challenge = self.transcript.get_challenge()
        self.gamma_challenge = gamma_challenge

        # Round 2: Generate and send permutation polynomial
        # This polynomial enforces that wire values are properly permuted
        # according to the circuit's wiring constraints
        self.instance.generate_permutation_polynomial(beta_challenge, gamma_challenge)

        # Commit and send the permutation polynomial
        self.transcript.send_to_verifier(
            map_tuple_from_int_to_Fq(
                self.kzg.commit(self.instance.all_polynomials.permutation)
            )
        )

        # Get challenge for zeta polynomial generation
        # This ensures each row is evaluated independently in the sumcheck
        zeta_challenge = self.transcript.get_challenge()
        self.zeta_challenge = zeta_challenge

        # Generate the zeta power polynomial for row independence
        self.instance.generate_zeta_power_polynomial(zeta_challenge)

        # Optional callback for testing or debugging
        before_sumcheck_update(self)

        # Prepare challenges for the sumcheck protocol
        sumcheck_challenges = SumcheckChallenges(zeta_challenge)
        relation_challenges = RelationChallenges(beta_challenge, gamma_challenge)

        # Round 3: Execute the sumcheck protocol
        # This proves that all circuit constraints are satisfied
        # The sumcheck reduces the high-dimensional polynomial evaluation
        # to a single point that the verifier can check directly
        sumcheck_prover = SumcheckProver(
            self.instance, self.transcript, sumcheck_challenges, relation_challenges
        )

        # Get the evaluation point from the sumcheck protocol
        # This point will be used to verify polynomial evaluations
        evaluation_point = sumcheck_prover.prove()

        # Round 4: Prove polynomial evaluations using Gemini protocol
        # Gemini is an efficient multilinear polynomial commitment scheme
        # that allows proving evaluations of multiple polynomials at once
        gemini_prover = GeminiProver(
            # Original polynomials (verification key + witness + derived)
            list(
                [
                    self.instance.all_polynomials[i]
                    for i in range(
                        NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS
                        + NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS
                        + DERIVED_POLYNOMIALS
                    )
                ]
            ),
            # Shifting polynomials (permutation and witness shifts)
            [
                self.instance.all_polynomials.permutation,
                self.instance.all_polynomials.w_l,
                self.instance.all_polynomials.w_r,
                self.instance.all_polynomials.w_o,
            ],
            self.transcript,
            evaluation_point,
        )

        # Get the opening claims that will be batched in the next round
        opening_claims = gemini_prover.prove()

        # Round 5: Batch verify all polynomial openings using Shplonk
        # Shplonk is a batched polynomial opening scheme that allows
        # verifying multiple polynomial evaluations efficiently
        shplonk_prover = ShplonkProver(opening_claims, self.transcript)
        shplonk_prover.prove()

    def export_proof(self):
        """
        Export the complete proof as a byte string.

        The proof contains all the information needed by the verifier to check
        that the circuit is satisfiable without revealing the witness values.

        The proof includes:
        - Verification key commitments
        - Witness commitments
        - Permutation polynomial commitment
        - Sumcheck protocol messages
        - Gemini protocol messages
        - Shplonk protocol messages

        Returns:
            bytes: Complete proof that can be verified by the Verifier class
        """
        return self.transcript.export_proof()


class Verifier:
    """
    The main verifier class that checks proofs for circuit satisfiability.

    The verifier receives a proof and verifies that it proves the existence of a
    valid witness satisfying all circuit constraints, without learning the actual
    witness values.

    The verification process mirrors the proving process:
    - Round 0: Receive and verify verification key
    - Round 1: Receive witness commitments
    - Round 2: Receive permutation polynomial commitment
    - Round 3: Verify sumcheck protocol
    - Round 4: Verify polynomial evaluations using Gemini
    - Round 5: Verify batched openings using Shplonk

    The verifier ensures that:
    - The verification key is consistent (if provided)
    - All circuit constraints are satisfied (sumcheck)
    - All polynomial evaluations are consistent with commitments
    - The proof is valid and complete
    """

    def __init__(self, proof_data: bytes):
        """
        Initialize the verifier with proof data.

        Args:
            proof_data: Complete proof as a byte string from the prover
        """
        self.transcript = VerifierTranscript(proof_data)

    def verify(self, verification_key=bytes([])):
        """
        Verify the complete proof.

        This method executes the full verification protocol in multiple rounds,
        mirroring the proving process. Each round verifies a specific aspect
        of the proof to ensure circuit satisfiability.

        Args:
            verification_key: Optional verification key to check consistency
                           (if not provided, only the proof is verified)

        Returns:
            bool: True if the proof is valid, False otherwise
        """
        # Round 0: Receive and verify verification key
        # Get the instance size (number of gates in the circuit)
        self.instance_size = self.transcript.get_int_from_prover()

        # Receive commitments to verification key polynomials
        # These are the circuit structure polynomials
        vk_commitments = []
        for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
            vk_commitments.append(self.transcript.get_point_from_prover())

        # If a verification key is provided, verify consistency
        # This ensures the proof was generated for the expected circuit
        if len(verification_key) != 0:
            vk_transcript = VerifierTranscript(verification_key)
            vk_instance_size = vk_transcript.get_int_from_prover()
            if vk_instance_size != self.instance_size:
                return False
            for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
                if vk_commitments[i] != vk_transcript.get_point_from_prover():
                    print("Verification Key Discrepancy")
                    return False

        # Round 1: Receive witness commitments
        # These are the actual witness values that prove circuit satisfiability
        initial_witness_commitments = []
        for i in range(
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS,
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS
            + NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS,
        ):
            initial_witness_commitments.append(self.transcript.get_point_from_prover())

        # Get the same challenges that the prover used
        # This ensures consistency between prover and verifier
        beta_challenge = self.transcript.get_challenge()
        gamma_challenge = self.transcript.get_challenge()

        # Round 2: Receive permutation polynomial commitment
        # This polynomial enforces wire permutation constraints
        permutation_commitment = self.transcript.get_point_from_prover()

        # Get the zeta challenge for sumcheck protocol
        zeta_challenge = self.transcript.get_challenge()

        # Prepare challenges for the sumcheck protocol
        sumcheck_challenges = SumcheckChallenges(zeta_challenge)
        relation_challenges = RelationChallenges(beta_challenge, gamma_challenge)

        # Round 3: Verify the sumcheck protocol
        # This proves that all circuit constraints are satisfied
        # The sumcheck reduces the high-dimensional polynomial evaluation
        # to a single point that we can verify directly
        sumcheck_verifier = SumcheckVerifier(
            self.instance_size,
            self.transcript,
            sumcheck_challenges,
            relation_challenges,
        )

        # Verify the sumcheck and get the evaluation point
        (sumcheck_verified, evaluation_point, polynomial_evaluations) = (
            sumcheck_verifier.verify()
        )

        if not sumcheck_verified:
            print("Sumcheck failed")
            return False

        # Round 4: Verify polynomial evaluations using Gemini protocol
        # Gemini verifies that the polynomial evaluations are consistent
        # with the commitments sent earlier
        gemini_verifier = GeminiVerifier(
            # Original polynomial commitments (verification key + witness + derived)
            vk_commitments + initial_witness_commitments + [permutation_commitment],
            # Shifting polynomial commitments (permutation and witness shifts)
            [
                permutation_commitment,
                initial_witness_commitments[0],
                initial_witness_commitments[1],
                initial_witness_commitments[2],
            ],
            self.transcript,
            evaluation_point,
            # Polynomial evaluations from sumcheck
            list(
                [polynomial_evaluations[i][0] for i in range(NUMBER_OF_POLYNOMIALS - 1)]
            ),
        )

        # Verify Gemini and get opening claims for Shplonk
        (gemini_verified, verifier_opening_claims) = gemini_verifier.verify()

        if not gemini_verified:
            print("Gemini failed")
            return False

        # Round 5: Verify batched polynomial openings using Shplonk
        # Shplonk efficiently verifies multiple polynomial openings at once
        # This is the final verification step that ensures all commitments
        # are consistent with the claimed evaluations
        shplonk_verifier = ShplonkVerifier(verifier_opening_claims, self.transcript)

        result = shplonk_verifier.verify()

        return result


class TestProver(unittest.TestCase):
    """
    Test class for the complete zero-knowledge proof protocol.

    This class tests the end-to-end functionality of the proof system,
    ensuring that valid proofs are generated and verified correctly.
    """

    def test_full_proof_with_vk(self):
        """
        Test the complete proof generation and verification process.

        This test:
        1. Creates a simple arithmetic circuit (a + b + c)
        2. Generates a verification key for the circuit
        3. Generates a proof for a valid witness
        4. Verifies the proof using the verification key

        This ensures that the entire protocol works correctly for valid inputs.
        """
        # Create a simple arithmetic circuit: a + b + c
        cb = CircuitBuilder()
        a = Fr_ct.create_witness(cb, Fr(0xFF))
        b = Fr_ct.create_witness(cb, Fr(0xF))
        c = Fr_ct.create_witness(cb, Fr(0xF0))
        d = a + b + c

        # Create prover and generate verification key
        prover = Prover(cb)
        verification_key = prover.generate_verification_key()

        # Generate proof for the circuit
        prover.prove()
        proof = prover.export_proof()

        # Verify the proof
        verfier = Verifier(proof)
        self.assertTrue(verfier.verify(verification_key=verification_key))


if __name__ == "__main__":
    unittest.main()
