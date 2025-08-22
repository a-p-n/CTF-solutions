#!/usr/bin/python3
# This file contains an implementation of Gemini multilinear polynomial commitment scheme

from transcript import ProverTranscript, VerifierTranscript, map_tuple_from_int_to_Fq
from ff import Fr, Fq
from kzg import KZG, batch_commitments, convert_to_working_point
from polynomial import (
    evaluate_multilinear_polynomial,
    partially_evaluate_multilinear_polynomial,
    evaluate_polynomial,
    batch_inverse,
    batch_polynomials,
)
from shplonk import ProverOpeningClaim, VerifierOpeningClaim
import unittest


class GeminiProver:
    def __init__(
        self,
        original_polynomials: list[list[Fr]],
        shifting_polynomials: list[list[Fr]],
        transcript: ProverTranscript,
        evaluation_point: list[Fr],
    ) -> list[ProverOpeningClaim]:
        self.original_polynomials = original_polynomials
        self.shifting_polynomials = shifting_polynomials
        self.transcript = transcript
        self.evaluation_point = evaluation_point
        self.challenge_index = 0
        self.commitments = []
        self.kzg = KZG()
        self.evaluations = []
        self.opening_claims = []

    def prove(self):
        # Get a batching challenge from the transcript
        self.rho = self.transcript.get_challenge()
        # Compute batched poly
        non_shifted_batch = batch_polynomials(
            [polynomial for polynomial in self.original_polynomials], self.rho
        )
        pre_shift_batch = batch_polynomials(
            [polynomial for polynomial in self.shifting_polynomials],
            self.rho,
            self.rho.pow(len(self.original_polynomials)),
        )
        # Check that the combination of the shifting polynomials has zero in the beginning
        assert pre_shift_batch[0] == Fr(0)
        # Start construction sequential polynomials for Gemini. The first one is the sum of the non-shifted and pre-shifted polynomials
        self.sequential_polynomials = [
            list(
                [
                    non_shifted_batch[i]
                    + pre_shift_batch[(i + 1) % len(non_shifted_batch)]
                    for i in range(len(non_shifted_batch))
                ]
            )
        ]

        # Commit to the first sequential polynomial
        self.transcript.send_to_verifier(
            map_tuple_from_int_to_Fq(self.kzg.commit(self.sequential_polynomials[0]))
        )

        # Compute partial evaluations of batched poly and commit to them
        for i in range(len(self.evaluation_point)):
            partially_evaluated = partially_evaluate_multilinear_polynomial(
                self.sequential_polynomials[-1],
                self.evaluation_point[self.challenge_index],
            )
            self.challenge_index += 1
            self.sequential_polynomials.append(partially_evaluated)
            partially_evaluated_commitment = self.kzg.commit(partially_evaluated)
            self.transcript.send_to_verifier(
                map_tuple_from_int_to_Fq(partially_evaluated_commitment)
            )

        # Get a challenge for the opening of all the sequential polynomials and the batched polynomials
        self.r = self.transcript.get_challenge()
        r = self.r

        # Add the the evaluation of the non-shifted polynomials at r
        self.evaluations.append(evaluate_polynomial(non_shifted_batch, r))
        self.opening_claims.append(
            ProverOpeningClaim(non_shifted_batch, r, self.evaluations[-1])
        )
        # Add the the evaluation of the pre-shifted polynomials at r
        self.evaluations.append(evaluate_polynomial(pre_shift_batch, r))
        self.opening_claims.append(
            ProverOpeningClaim(pre_shift_batch, r, self.evaluations[-1])
        )
        # Add the the evaluation of the first sequential polynomial at r
        self.evaluations.append(evaluate_polynomial(self.sequential_polynomials[0], r))
        self.opening_claims.append(
            ProverOpeningClaim(self.sequential_polynomials[0], r, self.evaluations[-1])
        )
        # Add the the evaluation of the first sequential polynomial at -r
        self.evaluations.append(evaluate_polynomial(self.sequential_polynomials[0], -r))
        self.opening_claims.append(
            ProverOpeningClaim(self.sequential_polynomials[0], -r, self.evaluations[-1])
        )

        # Add the the evaluation of the sequential polynomials at -r^(2^i)
        r_power = r
        for i in range(1, len(self.evaluation_point)):
            r_power *= r_power
            self.evaluations.append(
                evaluate_polynomial(self.sequential_polynomials[i], -r_power)
            )
            self.opening_claims.append(
                ProverOpeningClaim(
                    self.sequential_polynomials[i], -r_power, self.evaluations[-1]
                )
            )
        # Send the evaluations to the verifier
        for evaluation in self.evaluations:
            self.transcript.send_to_verifier(evaluation)
        # Return the opening claims for use in the Shplonk proof
        return self.opening_claims


class GeminiVerifier:
    def __init__(
        self,
        original_polynomial_commitments,
        shifting_polynomial_commitments,
        transcript: VerifierTranscript,
        evaluation_points,
        evaluations,
    ):
        self.original_commitments = original_polynomial_commitments
        self.shifting_commitments = shifting_polynomial_commitments
        self.transcript = transcript
        self.transcript = transcript
        self.evaluation_point = evaluation_points
        self.opening_claims = []
        self.original_evaluations = evaluations

    def verify(self):
        # Get a batching challenge from the transcript
        self.rho = self.transcript.get_challenge()
        # Compute batched commitments
        batched_original = batch_commitments(self.original_commitments, self.rho)
        batched_pre_shift = batch_commitments(
            self.shifting_commitments,
            self.rho,
            self.rho.pow(len(self.original_commitments)),
        )
        # Get the commitment to the new batch
        commitment_to_new_batch = convert_to_working_point(
            self.transcript.get_point_from_prover()
        )

        # The first two commitments need to be opened at r and -r
        commitments_for_opening = [
            commitment_to_new_batch,
            commitment_to_new_batch,
        ]
        # Compute partial evaluations of batched poly and commit to them
        for i in range(len(self.evaluation_point)):
            commitments_for_opening.append(
                convert_to_working_point((self.transcript.get_point_from_prover()))
            )
        # Get a challenge r for the opening of the batched polynomials
        self.r = self.transcript.get_challenge()
        r = self.r
        # Add the the evaluation of the non-shifted polynomials at r
        self.opening_claims.append(
            VerifierOpeningClaim(
                batched_original, r, self.transcript.get_Fr_from_prover()
            )
        )
        # Add the the evaluation of the pre-shifted polynomials at r
        self.opening_claims.append(
            VerifierOpeningClaim(
                batched_pre_shift, r, self.transcript.get_Fr_from_prover()
            )
        )
        # Add the the evaluation of the new batch at r
        self.opening_claims.append(
            VerifierOpeningClaim(
                commitment_to_new_batch, r, self.transcript.get_Fr_from_prover()
            )
        )
        # Check that the opening of batched original polynomials at r + the opening of batched pre-shifted polynomials at r divided by r equals the opening of the new batch at r
        if (
            self.opening_claims[0].y + (self.opening_claims[1].y / r)
        ) != self.opening_claims[2].y:
            # Gemini verification failed
            return (False, [])
        # Add the verification of the new batch at -r to shplonk's opening claims
        self.opening_claims.append(
            VerifierOpeningClaim(
                commitment_to_new_batch, -r, self.transcript.get_Fr_from_prover()
            )
        )
        power_of_r = r
        polynomial_for_inversion = [Fr(2), Fr(r)]
        # Get evaluations of sequential polynomials at -r^(2^i) and add them to shplonk's opening claims for verification
        for i in range(1, len(self.evaluation_point)):
            power_of_r *= power_of_r
            polynomial_for_inversion.append(power_of_r)
            self.opening_claims.append(
                VerifierOpeningClaim(
                    commitments_for_opening[i + 1],
                    -power_of_r,
                    self.transcript.get_Fr_from_prover(),
                )
            )

        useful_inverses = batch_inverse(polynomial_for_inversion)
        inv_2 = useful_inverses[0]
        r_power_inverses = useful_inverses[1:]

        previous_evaluation = Fr(0)
        # Check that sequential evaluations lead us to the correct multilinear polynomial evaluation
        for i, challenge in enumerate(self.evaluation_point):
            # The first evaluation is the opening of the new batch at r
            if i == 0:
                positive = self.opening_claims[2].y
            else:
                positive = previous_evaluation

            negative = self.opening_claims[i + 3].y
            # Compute the evaluation of a sequential polynomial at r^(2^i) by using the evaluations of the previous polynomial at r^(2^(i-1)) and -r^(2^(i-1))
            # f(x)=f_0(x^2)+x*f_1(x^2)
            # f(x)+f(-x)=2*f_0(x^2)
            # f(x)-f(-x)=2*x*f_1(x^2)
            even_coefficients = (positive + negative) * inv_2
            odd_coefficients = (positive - negative) * inv_2 * r_power_inverses[i]
            previous_evaluation = (
                even_coefficients + (odd_coefficients - even_coefficients) * challenge
            )
        final_evaluation = previous_evaluation
        original_batched_evaluations = batch_polynomials(
            [[x] for x in self.original_evaluations], self.rho
        )[0]

        return (final_evaluation == original_batched_evaluations, self.opening_claims)


from shplonk import ShplonkProver, ShplonkVerifier


class GeminiTest(unittest.TestCase):
    def test_correctness(self):
        kzg = KZG()
        prover_transcript = ProverTranscript()
        polynomial_1 = [Fr(1), Fr(1), Fr(1), Fr(1)]
        polynomial_2 = [Fr(2), Fr(2), Fr(2), Fr(3)]
        polynomial_3_for_shifting = [Fr(0), Fr(2), Fr(2), Fr(3)]
        polynomial_4_for_shifting = [Fr(0), Fr(10), Fr(15), Fr(3)]
        prover_transcript.send_to_verifier(Fr(2))
        evaluation_point = [Fr(3), Fr(4)]
        evaluations = [
            evaluate_multilinear_polynomial(polynomial_1, evaluation_point),
            evaluate_multilinear_polynomial(polynomial_2, evaluation_point),
            evaluate_multilinear_polynomial(
                polynomial_3_for_shifting[1:] + [Fr(0)], evaluation_point
            ),
            evaluate_multilinear_polynomial(
                polynomial_4_for_shifting[1:] + [Fr(0)], evaluation_point
            ),
        ]
        gemini_prover = GeminiProver(
            [polynomial_1, polynomial_2],
            [polynomial_3_for_shifting, polynomial_4_for_shifting],
            prover_transcript,
            evaluation_point,
        )
        prover_opening_claims = gemini_prover.prove()

        shplonk_prover = ShplonkProver(prover_opening_claims, prover_transcript)
        shplonk_prover.prove()

        verifier_transcript = VerifierTranscript(prover_transcript.export_proof())

        verifier_transcript.get_Fr_from_prover()

        gemini_verifier = GeminiVerifier(
            [kzg.commit(polynomial_1), kzg.commit(polynomial_2)],
            [
                kzg.commit(polynomial_3_for_shifting),
                kzg.commit(polynomial_4_for_shifting),
            ],
            verifier_transcript,
            evaluation_point,
            evaluations,
        )

        (gemini_verified, claims) = gemini_verifier.verify()
        self.assertTrue(gemini_verified)

        shplonk_verifier = ShplonkVerifier(claims, verifier_transcript)
        self.assertTrue(shplonk_verifier.verify())


if __name__ == "__main__":
    unittest.main()
