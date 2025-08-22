# This file is used to construct the circuit
from ff import Fr
from collections import namedtuple
import unittest

# Contains a gate description (selector values)
CircuitRow = namedtuple(
    "CircuitRow",
    ["q_m", "q_l", "q_r", "q_o", "q_c"],
    defaults=([Fr(0) for _ in range(5)]),
)

# Contains the witness indices for the gate
WitnessIndexRow = namedtuple(
    "WitnessIndexRow", ["w_l", "w_r", "w_o"], defaults=[0, 0, 0]
)

LAST_VARIABLE_IN_CLASS = -1
FIRST_VARIABLE_IN_CLASS = -1


class CircuitBuilder:
    """
    This class is used to construct the circuit.
    It contains the variables, the rows and the witness indices.
    """

    def add_variable(self, value: Fr):
        """Add a variable to the circuit. Variables with the same index are connected.
        The value is assigned to the variable at proving time, but it can be redefined by the prover
        """
        # Get next index
        index = len(self.variables)
        # Add the value of the variable to the list
        self.variables.append(value)
        # Add the index of the variable to the list of real variable indices (2 variables with the same index are connected)
        self.real_variable_indices.append(index)
        # Add the previous and next variable in the class (these are used to connect the variables during proving)
        self.previous_variable_in_class.append(FIRST_VARIABLE_IN_CLASS)
        self.next_variable_in_class.append(LAST_VARIABLE_IN_CLASS)
        return index

    def get_variable_value(self, index):
        """Get the value of a variable."""
        assert index < len(self.variables)
        return self.variables[self.real_variable_indices[index]]

    def connect(self, variable_index_1, variable_index_2, fail_on_inequality=True):
        """Connect two variables.
        If fail_on_inequality is True, the function will raise an error if the two variables have different values.
        """
        if fail_on_inequality:
            assert self.variables[variable_index_1] == self.variables[variable_index_2]
        last_variable = variable_index_1
        while self.next_variable_in_class[last_variable] != LAST_VARIABLE_IN_CLASS:
            last_variable = self.next_variable_in_class[last_variable]
        first_variable = variable_index_2
        while (
            self.previous_variable_in_class[first_variable] != FIRST_VARIABLE_IN_CLASS
        ):
            first_variable = self.previous_variable_in_class[first_variable]
        new_real_variable_index = self.real_variable_indices[variable_index_1]
        next_var = first_variable
        self.real_variable_indices[next_var] = new_real_variable_index
        while self.previous_variable_in_class[next_var] != LAST_VARIABLE_IN_CLASS:
            self.real_variable_indices[next_var] = new_real_variable_index
            next_var = self.previous_variable_in_class[next_var]
        self.previous_variable_in_class[first_variable] = last_variable
        self.next_variable_in_class[last_variable] = first_variable

    def __init__(self) -> None:
        """Initialize the circuit builder."""
        self.variables = []
        self.real_variable_indices = []
        self.previous_variable_in_class = []
        self.next_variable_in_class = []
        self.rows = []
        self.witness_indices = []
        self.zero_index = self.add_variable(Fr(0))
        self.one_index = self.add_variable(Fr(1))

        # # zero row for shifts
        self.rows.append(CircuitRow(Fr(0), Fr(0), Fr(0), Fr(0), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(self.zero_index, self.zero_index, self.zero_index)
        )
        # w_l[0] = 0
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(0), Fr(0), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(self.zero_index, self.zero_index, self.zero_index)
        )
        # w_l[1] = 1
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(0), Fr(0), Fr(-1)))
        self.witness_indices.append(
            WitnessIndexRow(self.one_index, self.zero_index, self.zero_index)
        )
        pass

    def create_poly_gate(self, selectors, indices):
        """Create a gate with the given selectors and witness indices."""
        self.rows.append(selectors)
        self.witness_indices.append(indices)

    def create_binary_gate(self, variable_index):
        """Create a gate that enforces the relation x²-x = 0"""
        assert variable_index < len(self.variables)
        self.rows.append(CircuitRow(Fr(1), Fr(-1), Fr(0), Fr(0), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(variable_index, variable_index, self.zero_index)
        )

    def create_addition_gate(self, input1_index, input2_index, output_index, constant):
        """output=input1 + input2 + constant"""
        assert input1_index < len(self.variables)
        assert input2_index < len(self.variables)
        assert output_index < len(self.variables)
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(1), Fr(-1), Fr(constant)))
        self.witness_indices.append(
            WitnessIndexRow(input1_index, input2_index, output_index)
        )

    def create_constant_gate(self, input_index, constant):
        """Create a gate that enforces the relation x - constant = 0"""
        assert input_index < len(self.variables)
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(0), Fr(0), -Fr(constant)))
        self.witness_indices.append(
            WitnessIndexRow(input_index, self.zero_index, self.zero_index)
        )

    def get_num_gates(self):
        """Get the number of gates in the circuit."""
        return len(self.rows)

    def create_multiplication_gate(self, input1_index, input2_index, output_index):
        """
        Create a multiplication gate that enforces output = input1 * input2.

        The gate enforces the constraint: q_m * input1 * input2 + q_l * input1 + q_r * input2 + q_o * output + q_c = 0
        For multiplication: q_m = 1, q_l = 0, q_r = 0, q_o = -1, q_c = 0
        This gives: input1 * input2 - output = 0, which means output = input1 * input2
        """
        assert input1_index < len(self.variables)
        assert input2_index < len(self.variables)
        assert output_index < len(self.variables)
        self.rows.append(CircuitRow(Fr(1), Fr(0), Fr(0), Fr(-1), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(input1_index, input2_index, output_index)
        )

    def create_negation_gate(self, input_index, output_index):
        """
        Create a negation gate that enforces output = -input.

        The gate enforces the constraint: q_m * input * input + q_l * input + q_r * input + q_o * output + q_c = 0
        For negation: q_m = 0, q_l = 1, q_r = 0, q_o = 1, q_c = 0
        This gives: input + output = 0, which means output = -input
        """
        assert input_index < len(self.variables)
        assert output_index < len(self.variables)
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(0), Fr(1), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(input_index, self.zero_index, output_index)
        )

    def print_gate(self, index):
        assert index < len(self.rows)
        assert len(self.rows) == len(self.witness_indices)
        selector_row = self.rows[index]
        witness_row = self.witness_indices[index]
        print(
            ("%04d: " % index)
            + f" arithmetic: {selector_row.q_m.value} * v_{witness_row.w_l} * v_{witness_row.w_r} + {selector_row.q_l.value} * v_{witness_row.w_l} + {selector_row.q_r.value} * v_{witness_row.w_r} + {selector_row.q_o.value} * v_{witness_row.w_o} + {selector_row.q_c.value}"
        )

    def print_circuit(self):
        for i in range(len(self.rows)):
            self.print_gate(i)

    def check_circuit(self):
        """Check the circuit for consistency."""
        for i in range(len(self.rows)):
            if not self.check_gate(i):
                print(f"Gate {i} is not consistent.")
                return False
        return True

    def check_gate(self, index):
        """Check the gate for consistency."""
        selector_row = self.rows[index]
        witness_row = self.witness_indices[index]
        return (
            selector_row.q_m
            * self.get_variable_value(witness_row.w_l)
            * self.get_variable_value(witness_row.w_r)
            + selector_row.q_l * self.get_variable_value(witness_row.w_l)
            + selector_row.q_r * self.get_variable_value(witness_row.w_r)
            + selector_row.q_o * self.get_variable_value(witness_row.w_o)
            + selector_row.q_c
            == 0
        )


class TestCircuitBuilder(unittest.TestCase):
    def test_correct_circuit(self):
        cb = CircuitBuilder()
        a = cb.add_variable(Fr(3))
        b = cb.add_variable(Fr(5))
        out = cb.add_variable(Fr(15))
        cb.create_multiplication_gate(a, b, out)
        self.assertTrue(cb.check_circuit())

    def test_failing_circuit(self):
        cb = CircuitBuilder()
        a = cb.add_variable(Fr(3))
        b = cb.add_variable(Fr(5))
        out = cb.add_variable(Fr(999))  # Wrong output
        cb.create_multiplication_gate(a, b, out)
        self.assertFalse(cb.check_circuit())

    def test_fix_failing_circuit(self):
        cb = CircuitBuilder()
        a = cb.add_variable(Fr(3))
        b = cb.add_variable(Fr(5))
        out = cb.add_variable(Fr(999))  # Wrong output
        cb.create_multiplication_gate(a, b, out)
        self.assertFalse(cb.check_circuit())
        # Fix the output
        cb.variables[out] = Fr(15)
        self.assertTrue(cb.check_circuit())

    def test_addition_gate(self):
        cb = CircuitBuilder()
        a = cb.add_variable(Fr(2))
        b = cb.add_variable(Fr(4))
        out = cb.add_variable(Fr(7))  # 2+4+1=7
        cb.create_addition_gate(a, b, out, constant=1)
        self.assertTrue(cb.check_circuit())
        # Failing case
        cb2 = CircuitBuilder()
        a2 = cb2.add_variable(Fr(2))
        b2 = cb2.add_variable(Fr(4))
        out2 = cb2.add_variable(Fr(8))  # Wrong
        cb2.create_addition_gate(a2, b2, out2, constant=1)
        self.assertFalse(cb2.check_circuit())

    def test_constant_gate(self):
        cb = CircuitBuilder()
        a = cb.add_variable(Fr(42))
        cb.create_constant_gate(a, constant=42)
        self.assertTrue(cb.check_circuit())
        # Failing case
        cb2 = CircuitBuilder()
        a2 = cb2.add_variable(Fr(41))
        cb2.create_constant_gate(a2, constant=42)
        self.assertFalse(cb2.check_circuit())

    def test_binary_gate(self):
        cb = CircuitBuilder()
        a = cb.add_variable(Fr(0))
        cb.create_binary_gate(a)  # 0^2 - 0 = 0
        a2 = cb.add_variable(Fr(1))
        cb.create_binary_gate(a2)  # 1^2 - 1 = 0
        self.assertTrue(cb.check_circuit())
        # Failing case
        cb2 = CircuitBuilder()
        a3 = cb2.add_variable(Fr(2))
        cb2.create_binary_gate(a3)  # 2^2 - 2 != 0
        self.assertFalse(cb2.check_circuit())

    def test_negation_gate(self):
        cb = CircuitBuilder()
        a = cb.add_variable(Fr(7))
        out = cb.add_variable(Fr(-7))
        cb.create_negation_gate(a, out)
        self.assertTrue(cb.check_circuit())
        # Failing case
        cb2 = CircuitBuilder()
        a2 = cb2.add_variable(Fr(7))
        out2 = cb2.add_variable(Fr(-6))
        cb2.create_negation_gate(a2, out2)
        self.assertFalse(cb2.check_circuit())

    def test_poly_gate(self):
        cb = CircuitBuilder()
        # Custom: 2*x + 3*y - z + 5 = 0, x=1, y=2, z=13 (2*1+3*2-13+5=0)
        x = cb.add_variable(Fr(1))
        y = cb.add_variable(Fr(2))
        z = cb.add_variable(Fr(13))
        selectors = CircuitRow(Fr(0), Fr(2), Fr(3), Fr(-1), Fr(5))
        indices = WitnessIndexRow(x, y, z)
        cb.create_poly_gate(selectors, indices)
        self.assertTrue(cb.check_circuit())
        # Failing case
        cb2 = CircuitBuilder()
        x2 = cb2.add_variable(Fr(1))
        y2 = cb2.add_variable(Fr(2))
        z2 = cb2.add_variable(Fr(8))  # Wrong
        selectors2 = CircuitRow(Fr(0), Fr(2), Fr(3), Fr(-1), Fr(5))
        indices2 = WitnessIndexRow(x2, y2, z2)
        cb2.create_poly_gate(selectors2, indices2)
        self.assertFalse(cb2.check_circuit())


if __name__ == "__main__":

    # Run unittests
    unittest.main()
