# This file contains the sumcheck protocol
from instance import AllPolynomials, Instance, NUMBER_OF_POLYNOMIALS
from relations import (
    ArithmeticRelation,
    PermutationConsequentRelationNoPublicInputs,
    PermutationRelationLastElement,
    RelationChallenges,
)
from transcript import ProverTranscript, VerifierTranscript
from copy import deepcopy
import unittest
from ff import Fr
from ff_ct import Fr_ct
from collections import namedtuple
from polynomial import (
    partially_evaluate_multilinear_polynomial,
    convert_from_lagrange_to_monomial_form,
    evaluate_polynomial,
    batch_polynomials,
)

SumcheckChallenges = namedtuple("SumcheckChallenges", ["zeta"], defaults=[Fr(-1)])
# zeta: Field element used as the base for generating row-specific powers in the sumcheck protocol.
# This ensures each row of the circuit is evaluated independently during the sumcheck.


def evaluate_multilinear_zeta_power_polynomial(challenges, zeta):
    """
    Evaluates the multilinear zeta power polynomial at the given challenges.

    This function computes the evaluation of a special polynomial that ensures
    the sumcheck protocol correctly verifies that each row of the circuit
    independently satisfies the constraint relations. The zeta polynomial acts
    as a "row separator" that prevents cross-row interference in the sumcheck.

    Mathematical description:
    - The polynomial is constructed as: ∏(1 + challenge_i * (zeta^(2^i) - 1))
    - Where challenge_i are the sumcheck round challenges and zeta is the base
    - This creates a unique "fingerprint" for each row that the verifier can
      independently compute and verify

    Args:
        challenges: List of sumcheck round challenges (one per round)
        zeta: The base field element used to generate row-specific powers

    Returns:
        The evaluation of the multilinear zeta power polynomial
    """
    result = Fr(1)
    current_power = zeta
    for challenge in challenges:
        difference = current_power - Fr(1)
        result *= Fr(1) + challenge * difference
        current_power *= current_power
    return result


def take_cube_edges(round_polynomials: AllPolynomials, index: int):
    """Construct the edges of the cube for the given index
    This is use to compute the sumcheck relations on a particular edge of the hypercube
    """
    edges = AllPolynomials(*([[] for _ in range(NUMBER_OF_POLYNOMIALS)]))
    for round_polynomial, edge in zip(round_polynomials, edges):
        edge.append(round_polynomial[index * 2])
        edge.append(round_polynomial[index * 2 + 1])
    return edges


def extend_edges(edges: AllPolynomials, length: int):
    """Extend the edges of the cube to the given length. We take evaluations at 0 and 1 and then interpolate to get the evaluations at 2,3,4,5...
    This is used to compute the sumcheck relations on a particular edge of the hypercube
    """
    extended_edges = AllPolynomials(*([[] for _ in range(NUMBER_OF_POLYNOMIALS)]))
    for edge, extended_edge in zip(edges, extended_edges):
        difference = edge[1] - edge[0]
        for i in range(2):
            extended_edge.append(edge[i])
        for i in range(2, length):
            extended_edge.append(extended_edge[i - 1] + difference)
    return extended_edges


def partially_evaluate_all_polynomials(
    round_polynomials: AllPolynomials, challenge: Fr
):
    round_length = len(round_polynomials[0])
    assert round_length >= 2 and round_length % 2 == 0
    new_round_polynomials = AllPolynomials(
        *([[] for _ in range(NUMBER_OF_POLYNOMIALS)])
    )
    for old_polynomial, new_polynomial in zip(round_polynomials, new_round_polynomials):
        new_polynomial.extend(
            partially_evaluate_multilinear_polynomial(old_polynomial, challenge)
        )
    return new_round_polynomials


class SumcheckProver:
    def __init__(
        self,
        instance: Instance,
        transcript: ProverTranscript,
        sumcheck_challenges: SumcheckChallenges,
        relation_challenges: RelationChallenges,
    ):
        self.transcript = transcript
        self.sumcheck_challenges = sumcheck_challenges
        self.instance = instance
        self.currentPolynomials = deepcopy(instance.all_polynomials)
        self.per_row_relations = [
            ArithmeticRelation(relation_challenges),
            PermutationConsequentRelationNoPublicInputs(relation_challenges),
            PermutationRelationLastElement(relation_challenges),
        ]
        max_degree = 0
        for relation in self.per_row_relations:
            max_degree = max(max_degree, relation.get_degree())
        self.extended_length = max_degree + 2  # 1 for degree -> coeff  + 1 for zeta
        self.round_challenges = []

    def prove_round(self):

        round_size = len(self.currentPolynomials[0])
        assert round_size > 1
        # We ignore the efficiency of using the lower degree of some relations, since it's only going to be a very small workload and just use the maximum
        result = [Fr(0) for _ in range(self.extended_length)]
        per_row_relations_alpha_power = Fr(1)
        for i in range(0, round_size // 2):
            # Take edges
            edges = take_cube_edges(self.currentPolynomials, i)

            # Interpolate polynomials on the edge
            extended_edges = extend_edges(edges, self.extended_length)

            # Evaluate relations
            per_row_relations_results = [
                relation.evaluate(extended_edges) for relation in self.per_row_relations
            ]

            # Batch polynomials
            batched_per_row_relations_results = batch_polynomials(
                per_row_relations_results, self.alpha, per_row_relations_alpha_power
            )
            # Multiply by zeta powers to ensure each row is evaluated independently
            # The zeta powers act as row-specific weights that prevent cross-row interference
            for j in range(self.extended_length):
                result[j] += (
                    batched_per_row_relations_results[j] * extended_edges.zeta_powers[j]
                )

        # Send the round polynomial to the verifier
        for element in result:
            self.transcript.send_to_verifier(element)
        # Get the sumcheck round challenge
        sumcheck_round_challenge = self.transcript.get_challenge()
        self.round_challenges.append(sumcheck_round_challenge)
        # Partially evaluate the polynomials
        self.currentPolynomials = partially_evaluate_all_polynomials(
            self.currentPolynomials, sumcheck_round_challenge
        )

    def prove(self):
        # Get the sumcheck relation batching challenge
        self.alpha = self.transcript.get_challenge()
        instance_size = len(self.currentPolynomials[0])
        # Prove sumcheck for each round
        for i in range(instance_size.bit_length() - 1):
            self.prove_round()

        assert len(self.currentPolynomials[0]) == 1
        # Send final polynomial evaluations to the verifier
        for i, multilinear_polynomial_evaluation in enumerate(self.currentPolynomials):
            self.transcript.send_to_verifier(multilinear_polynomial_evaluation[0])
        return self.round_challenges


class SumcheckVerifier:
    def __init__(
        self,
        instance_size: int,
        transcript: VerifierTranscript,
        challenges: SumcheckChallenges,
        relation_challenges: RelationChallenges,
    ):
        self.transcript = transcript
        self.sumcheck_challenges = challenges

        self.per_row_relations = [
            ArithmeticRelation(relation_challenges),
            PermutationConsequentRelationNoPublicInputs(relation_challenges),
            PermutationRelationLastElement(relation_challenges),
        ]
        self.target_sum = Fr(0)
        self.instance_size = instance_size
        max_degree = 0
        for relation in self.per_row_relations:
            max_degree = max(max_degree, relation.get_degree())
        self.extended_length = max_degree + 2
        self.round_challenges = []

    def verify_round(self) -> bool:
        """Verify one round of the sumcheck protocol"""
        round_univariate = []
        # Get the round polynomial from the prover
        for i in range(self.extended_length):
            round_univariate.append(self.transcript.get_Fr_from_prover())

        # Check that the sum of evaluations at 0 and 1 is equal to the target sum (0 in the first round)
        if round_univariate[0] + round_univariate[1] != self.target_sum:
            return False
        # Get the sumcheck round challenge
        round_challenge = self.transcript.get_challenge()
        # Append the challenge to the list of round challenges
        self.round_challenges.append(round_challenge)

        # Convert the round polynomial to coefficient form
        monomial = convert_from_lagrange_to_monomial_form(round_univariate)
        # Evaluate the polynomial at the challenge
        monomial_at_challenge = evaluate_polynomial(monomial, round_challenge)
        # Update the target sum
        self.target_sum = monomial_at_challenge

        return True

    def verify(self):
        """Verify the sumcheck protocol"""
        # Get the sumcheck relation batching challenge
        self.alpha = self.transcript.get_challenge()
        # Verify each round
        per_row_relations_alpha_power = Fr(1)
        for i in range(self.instance_size.bit_length() - 1):
            round_result = self.verify_round()
            if not round_result:
                return (False, Fr(0), [])
        # Get the final polynomial evaluations from the prover
        polynomial_evaluations = AllPolynomials(
            *(
                [
                    [self.transcript.get_Fr_from_prover()]
                    for _ in range(NUMBER_OF_POLYNOMIALS)
                ]
            )
        )

        batched_per_row_relations_result = batch_polynomials(
            [
                relation.evaluate(polynomial_evaluations)
                for relation in self.per_row_relations
            ],
            self.alpha,
            per_row_relations_alpha_power,
        )
        full_sum = (
            batched_per_row_relations_result[0] * polynomial_evaluations.zeta_powers[0]
        )
        # Verify that the sumcheck protocol correctly computed the constraint sum
        # and that the zeta power polynomial evaluation matches the expected value
        # This ensures that each row was properly weighted and the constraints hold
        return (
            full_sum == self.target_sum
            and polynomial_evaluations.zeta_powers[0]
            == evaluate_multilinear_zeta_power_polynomial(
                self.round_challenges, self.sumcheck_challenges.zeta
            ),
            self.round_challenges,
            polynomial_evaluations,
        )


class SumcheckProverTest(unittest.TestCase):
    def test_one_round(self):
        from circuit import CircuitBuilder
        from transcript import ProverTranscript

        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(Fr(1))
        cb = CircuitBuilder()
        a = Fr_ct.create_witness(cb, 1)
        b = Fr_ct.create_witness(cb, 2)
        a = a + b
        a = a + b
        b = a + b
        instance = Instance(cb)
        instance.generate_zeta_power_polynomial(Fr(2))
        sumcheck_challenges = SumcheckChallenges(zeta=Fr(2))
        relation_challenges = RelationChallenges(Fr(10), Fr(11))
        instance.generate_permutation_polynomial(
            relation_challenges.beta, relation_challenges.gamma
        )
        sumcheck_prover = SumcheckProver(
            instance, prover_transcript, sumcheck_challenges, relation_challenges
        )

        sumcheck_prover.alpha = Fr(-1)
        sumcheck_prover.prove_round()
        round_proof = prover_transcript.export_proof()
        verifier_transcript = VerifierTranscript(round_proof)
        verifier_transcript.get_Fr_from_prover()
        sumcheck_verifier = SumcheckVerifier(
            instance.instance_size,
            verifier_transcript,
            sumcheck_challenges,
            relation_challenges,
        )
        sumcheck_verifier.alpha = Fr(-1)
        result = sumcheck_verifier.verify_round()
        self.assertTrue(result)

    def test_full(self):
        from circuit import CircuitBuilder
        from transcript import ProverTranscript

        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(Fr(1))
        cb = CircuitBuilder()
        a = Fr_ct.create_witness(cb, 1)
        b = Fr_ct.create_witness(cb, 2)
        a = a + b
        a = a + b
        b = a + b
        instance = Instance(cb)
        instance.generate_zeta_power_polynomial(Fr(2))
        sumcheck_challenges = SumcheckChallenges(zeta=Fr(2))
        relation_challenges = RelationChallenges(Fr(10), Fr(11))
        instance.generate_permutation_polynomial(
            relation_challenges.beta, relation_challenges.gamma
        )
        sumcheck_prover = SumcheckProver(
            instance, prover_transcript, sumcheck_challenges, relation_challenges
        )
        sumcheck_prover.prove()
        round_proof = prover_transcript.export_proof()
        verifier_transcript = VerifierTranscript(round_proof)
        verifier_transcript.get_Fr_from_prover()
        sumcheck_verifier = SumcheckVerifier(
            instance.instance_size,
            verifier_transcript,
            sumcheck_challenges,
            relation_challenges,
        )
        (success, round_challenges, resulting_evaluation) = sumcheck_verifier.verify()
        self.assertTrue(success)


if __name__ == "__main__":
    unittest.main()
