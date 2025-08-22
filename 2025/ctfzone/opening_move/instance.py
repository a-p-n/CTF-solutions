# This file is used to generate the witness polynomials for the prover from the description of the circuit
from ff_ct import Fr_ct
from polynomial import batch_inverse
from circuit import CircuitBuilder
from ff import Fr, alt_bn128_r
from collections import namedtuple
from relations import PermutationConsequentRelationNoPublicInputs, RelationChallenges
import random
import unittest
from proof_polynomials import *


def compute_permutation_mapping(circuit_builder: CircuitBuilder):
    """Compute the permutation map of the circuit. It is used to compute SIGMA polynomials that enforce the permutation relation."""
    num_gates = circuit_builder.get_num_gates()
    cycles = dict()

    def add_to_cycle(gate_index, polynomial_index, real_variable_index):
        if real_variable_index in cycles.keys():
            cycles[real_variable_index].extend([(gate_index, polynomial_index)])
        else:
            cycles[real_variable_index] = [(gate_index, polynomial_index)]

    for i in range(num_gates):
        witness_indices = circuit_builder.witness_indices[i]
        real_index_w_l = circuit_builder.real_variable_indices[witness_indices.w_l]
        real_index_w_r = circuit_builder.real_variable_indices[witness_indices.w_r]
        real_index_w_o = circuit_builder.real_variable_indices[witness_indices.w_o]
        add_to_cycle(i, 0, real_index_w_l)
        add_to_cycle(i, 1, real_index_w_r)
        add_to_cycle(i, 2, real_index_w_o)

    permutation_map = dict()
    for key in cycles.keys():
        cycle_permutation = cycles[key]
        for i in range(len(cycle_permutation)):
            permutation_map[cycle_permutation[i]] = cycle_permutation[
                (i + 1) % len(cycle_permutation)
            ]
    return permutation_map


class Instance:

    def __init__(self, circuit_builder):
        """Generate the witness polynomials for the prover from the description of the circuit."""
        self.builder = circuit_builder

        num_gates = circuit_builder.get_num_gates()

        # The instance size is the number of gates
        self.instance_size = 2 << (num_gates - 1).bit_length()
        instance_size = self.instance_size

        # Initialize the polynomials
        self.all_polynomials = AllPolynomials(
            *[[] for _ in range(NUMBER_OF_POLYNOMIALS)]
        )

        # Compute the permutation map
        permutation_map = compute_permutation_mapping(circuit_builder)

        # Fill lagrange polynomials
        self.all_polynomials.lagrange_first.extend(
            [Fr(0) for _ in range(self.instance_size)]
        )
        self.all_polynomials.lagrange_first[0] = Fr(1)

        self.all_polynomials.lagrange_last.extend(
            [Fr(0) for _ in range(self.instance_size)]
        )
        self.all_polynomials.lagrange_last[-1] = Fr(1)

        # Fill id and sigma polynomials
        for i in range(instance_size):
            # Fill id polynomials with sequential values
            # left is 1, 2, 3, ...
            # right is 1 + instance_size, 2 + instance_size, 3 + instance_size, ...
            # output is 1 + 2 * instance_size, 2 + 2 * instance_size, 3 + 2 * instance_size, ...
            self.all_polynomials.id_l.append(Fr(i + 1))
            self.all_polynomials.id_r.append(Fr(i + 1 + instance_size))
            self.all_polynomials.id_o.append(Fr(i + 1 + 2 * instance_size))
            # Compute the next left, right and output indices
            next_left = (
                permutation_map[(i, 0)] if (i, 0) in permutation_map.keys() else (i, 0)
            )
            next_right = (
                permutation_map[(i, 1)] if (i, 1) in permutation_map.keys() else (i, 1)
            )
            next_output = (
                permutation_map[(i, 2)] if (i, 2) in permutation_map.keys() else (i, 2)
            )
            self.all_polynomials.sigma_l.append(
                Fr(1 + next_left[0] + next_left[1] * instance_size)
            )
            self.all_polynomials.sigma_r.append(
                Fr(1 + next_right[0] + next_right[1] * instance_size)
            )
            self.all_polynomials.sigma_o.append(
                Fr(1 + next_output[0] + next_output[1] * instance_size)
            )
        # Fill selectors from circuit rows
        for i in range(num_gates):
            selector_row = circuit_builder.rows[i]
            self.all_polynomials.q_m.append(selector_row.q_m)
            self.all_polynomials.q_l.append(selector_row.q_l)
            self.all_polynomials.q_r.append(selector_row.q_r)
            self.all_polynomials.q_o.append(selector_row.q_o)
            self.all_polynomials.q_c.append(selector_row.q_c)
        # Fill selectors for the remaining rows
        for i in range(self.instance_size - num_gates):
            self.all_polynomials.q_m.append(Fr(0))
            self.all_polynomials.q_l.append(Fr(0))
            self.all_polynomials.q_r.append(Fr(0))
            self.all_polynomials.q_o.append(Fr(0))
            self.all_polynomials.q_c.append(Fr(0))

        # Fill witnesses
        for i in range(num_gates):
            witness_indices = self.builder.witness_indices[i]
            self.all_polynomials.w_l.append(
                Fr(self.builder.get_variable_value(witness_indices.w_l))
            )
            self.all_polynomials.w_r.append(
                Fr(self.builder.get_variable_value(witness_indices.w_r))
            )
            self.all_polynomials.w_o.append(
                Fr(self.builder.get_variable_value(witness_indices.w_o))
            )

        for i in range(self.instance_size - num_gates):
            self.all_polynomials.w_l.append(Fr(0))
            self.all_polynomials.w_r.append(Fr(0))
            self.all_polynomials.w_o.append(Fr(0))
        self.all_polynomials.w_l_shift.extend(self.all_polynomials.w_l[1:] + [Fr(0)])
        self.all_polynomials.w_r_shift.extend(self.all_polynomials.w_r[1:] + [Fr(0)])
        self.all_polynomials.w_o_shift.extend(self.all_polynomials.w_o[1:] + [Fr(0)])

    def generate_zeta_power_polynomial(self, zeta):
        """Generate the zeta power polynomial. This is used to ensure that the sumcheck verifies that each row is independently zero"""
        current_power = Fr(1)
        for _ in range(self.instance_size):
            self.all_polynomials.zeta_powers.append(current_power)
            current_power *= zeta

    def generate_permutation_polynomial(self, beta, gamma):
        """Generate the permutation polynomial. This is used to ensure that the permutation relation is satisfied."""
        numerators = [Fr(1)]
        denominators = [Fr(1)]
        permutation_relation = PermutationConsequentRelationNoPublicInputs(
            RelationChallenges(beta, gamma)
        )
        for i in range(self.instance_size):
            numerators.append(
                numerators[-1]
                * permutation_relation.compute_numerator(self.all_polynomials, i)
            )
            denominators.append(
                denominators[-1]
                * permutation_relation.compute_denominator(self.all_polynomials, i)
            )
        denominators = batch_inverse(denominators)

        permutation_pre_polynomial = [a * b for (a, b) in zip(numerators, denominators)]
        assert permutation_pre_polynomial[-1] == Fr(1)
        self.all_polynomials.permutation.extend(
            [Fr(0)] + [Fr(x) for x in permutation_pre_polynomial[1:-1]]
        )
        self.all_polynomials.permutation_shift.extend(
            [Fr(x) for x in permutation_pre_polynomial[1:-1]] + [Fr(0)]
        )


class TestInstance(unittest.TestCase):

    def test_batch_inverse(self):
        polynomial = [Fr(i + 1) for i in range(10)]
        inverse_polynomial = batch_inverse(polynomial)
        self.assertEqual(len(polynomial), len(inverse_polynomial))
        for a, b in zip(polynomial, inverse_polynomial):
            self.assertEqual(a * b, Fr(1))

    def test_polynomial_creation(self):
        cb = CircuitBuilder()
        a = Fr_ct.create_witness(cb, Fr(0xFF))
        b = Fr_ct.create_witness(cb, Fr(0xF))
        c = Fr_ct.create_witness(cb, Fr(0xF0))
        d = a + b + c
        self.assertTrue(d.get_value() == 0x1FE)
        instance = Instance(cb)
        instance_size = instance.instance_size

        def to_printable_list(polynomial, size):
            return list(
                map(
                    lambda x: x.value if type(x) == Fr else x,
                    polynomial[:size],
                )
            )

        print("id_l[:%d]:" % instance_size)
        print(to_printable_list(instance.all_polynomials.id_l, instance_size))
        print("id_r[:%d]:" % instance_size)
        print(to_printable_list(instance.all_polynomials.id_r, instance_size))
        print("id_o[:%d]:" % instance_size)
        print(to_printable_list(instance.all_polynomials.id_o, instance_size))
        beta = Fr.from_bytes(random.randbytes(32))
        gamma = Fr.from_bytes(random.randbytes(32))
        left = Fr(1)
        right = Fr(1)
        for i in range(instance_size):
            left *= (
                instance.all_polynomials.w_l[i]
                + instance.all_polynomials.id_l[i] * beta
                + gamma
            )
            left *= (
                instance.all_polynomials.w_r[i]
                + instance.all_polynomials.id_r[i] * beta
                + gamma
            )
            left *= (
                instance.all_polynomials.w_o[i]
                + instance.all_polynomials.id_o[i] * beta
                + gamma
            )

            right *= (
                instance.all_polynomials.w_l[i]
                + instance.all_polynomials.sigma_l[i] * beta
                + gamma
            )
            right *= (
                instance.all_polynomials.w_r[i]
                + instance.all_polynomials.sigma_r[i] * beta
                + gamma
            )
            right *= (
                instance.all_polynomials.w_o[i]
                + instance.all_polynomials.sigma_o[i] * beta
                + gamma
            )
        self.assertEqual(left, right, "Permutation check fails")

        print("sigma_l[:%d]:" % instance_size)
        print(to_printable_list(instance.all_polynomials.sigma_l, instance_size))
        print("sigma_r[:%d]:" % instance_size)
        print(to_printable_list(instance.all_polynomials.sigma_r, instance_size))
        print("sigma_o[:%d]:" % instance_size)
        print(to_printable_list(instance.all_polynomials.sigma_o, instance_size))


if __name__ == "__main__":
    unittest.main()
