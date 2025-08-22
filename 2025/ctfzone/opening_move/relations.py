from ff import Fr
from proof_polynomials import AllPolynomials
from collections import namedtuple

RelationChallenges = namedtuple(
    "AllPolynomials", ["beta", "gamma"], defaults=[Fr(-2), Fr(-1)]
)


class ArithmeticRelation:
    """Enforces the arithmetic relation:  (q_m * w_l * w_r + q_l * w_l + q_r * w_r + q_o * w_o + q_c) = 0"""

    def __init__(self, challenges):
        pass

    def get_degree(self):
        """Get the power of the relation polynomial"""
        return 3

    def evaluate(self, all_polynomials: AllPolynomials):
        result = []
        for i in range(len(all_polynomials.q_m)):
            result.append(
                (
                    all_polynomials.q_m[i]
                    * all_polynomials.w_l[i]
                    * all_polynomials.w_r[i]
                    + all_polynomials.q_l[i] * all_polynomials.w_l[i]
                    + all_polynomials.q_r[i] * all_polynomials.w_r[i]
                    + all_polynomials.q_o[i] * all_polynomials.w_o[i]
                    + all_polynomials.q_c[i]
                )
            )
        return result


class PermutationConsequentRelationNoPublicInputs:
    """Enforces the permutation relation:
    (lagrange_first+permutation) * (id_l + w_l * beta + gamma)
    * (id_r + w_r * beta + gamma) * (id_o + w_o * beta + gamma)
    - (lagrange_last + permutation_shift) * (sigma_l + w_l * beta + gamma) * (sigma_r + w_r * beta + gamma)
    * (sigma_o + w_o * beta + gamma) = 0"""

    def __init__(self, challenges: RelationChallenges):
        self.challenges = challenges
        pass

    def get_degree(self):
        return 5

    def compute_numerator(self, all_polynomials: AllPolynomials, i: int):
        (beta, gamma) = self.challenges.beta, self.challenges.gamma
        return (
            (all_polynomials.id_l[i] + all_polynomials.w_l[i] * beta + gamma)
            * (all_polynomials.id_r[i] + all_polynomials.w_r[i] * beta + gamma)
            * (all_polynomials.id_o[i] + all_polynomials.w_o[i] * beta + gamma)
        )

    def compute_denominator(self, all_polynomials: AllPolynomials, i: int):
        (beta, gamma) = self.challenges.beta, self.challenges.gamma
        return (
            (all_polynomials.sigma_l[i] + all_polynomials.w_l[i] * beta + gamma)
            * (all_polynomials.sigma_r[i] + all_polynomials.w_r[i] * beta + gamma)
            * (all_polynomials.sigma_o[i] + all_polynomials.w_o[i] * beta + gamma)
        )

    def evaluate(self, all_polynomials: AllPolynomials):
        result = []
        for i in range(len(all_polynomials.permutation)):
            result.append(
                (
                    (all_polynomials.lagrange_first[i] + all_polynomials.permutation[i])
                    * self.compute_numerator(all_polynomials, i)
                )
                - (
                    (
                        all_polynomials.permutation_shift[i]
                        + all_polynomials.lagrange_last[i]
                    )
                    * self.compute_denominator(all_polynomials, i)
                )
            )
        return result


class PermutationRelationLastElement:
    """Enforces the permutation relation: lagrange_last * permutation_shift = 0"""

    def __init__(self, challenges: RelationChallenges):
        self.challenges = challenges
        pass

    def get_degree(self):
        return 2

    def evaluate(self, all_polynomials: AllPolynomials):
        result = []
        for i in range(len(all_polynomials.permutation)):
            result.append(
                all_polynomials.lagrange_last[i] * all_polynomials.permutation_shift[i]
            )
        return result
