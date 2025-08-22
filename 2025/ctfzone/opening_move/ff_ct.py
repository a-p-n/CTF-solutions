# This file contains the logic for an in-circuit field type. Only addition is implemented
from ff import Fr
from circuit import CircuitBuilder, CircuitRow, WitnessIndexRow
import unittest


class Fr_ct:
    multiplicative_constant = Fr(0)
    witness_index = -1
    additive_constant = Fr(0)
    builder = None

    def __init__(
        self,
        additive_constant_=Fr(0),
        multiplicative_constant_=Fr(0),
        witness_index=-1,
        builder=None,
    ):
        """Initialize a field element within the circuit"""
        self.builder = builder
        self.multiplicative_constant = Fr(multiplicative_constant_)
        self.additive_constant = Fr(additive_constant_)
        self.witness_index = witness_index

    @staticmethod
    def create_witness(builder, field_value):
        """Create an unconstrained field element within the circuit with a given value"""
        field_value = Fr(field_value)
        temp = Fr_ct()
        temp.builder = builder
        temp.multiplicative_constant = Fr(1)
        temp.additive_constant = Fr(0)
        temp.witness_index = builder.add_variable(field_value)
        return temp

    def get_value(self):
        return (
            self.builder.get_variable_value(self.witness_index)
            * self.multiplicative_constant
            + self.additive_constant
        )

    def normalize(self):
        if self.multiplicative_constant == Fr(0):
            return self

        new_value = (
            self.multiplicative_constant
            * self.builder.get_variable_value(self.witness_index)
            + self.additive_constant
        )

        new_index = self.builder.add_variable(new_value)

        self.builder.create_poly_gate(
            CircuitRow(
                Fr(0),
                self.multiplicative_constant,
                Fr(0),
                Fr(-1),
                self.additive_constant,
            ),
            WitnessIndexRow(self.witness_index, self.builder.zero_index, new_index),
        )

        return Fr_ct(Fr(0), Fr(1), new_index, self.builder)

    def constrain(self, value=None):
        if value is None:
            value = self.get_value()
        if self.multiplicative_constant == Fr(0):
            return
        else:
            self.builder.create_poly_gate(
                CircuitRow(
                    Fr(0),
                    Fr(self.multiplicative_constant),
                    Fr(0),
                    Fr(0),
                    self.additive_constant - value,
                ),
                WitnessIndexRow(
                    self.witness_index, self.builder.zero_index, self.builder.zero_index
                ),
            )
        return self

    def __add__(self, other):
        """Add two elements together"""
        if self.multiplicative_constant == Fr(0):
            if other.multiplicative_constant == Fr(0):
                # Adding two constants
                return Fr_ct(self.additive_constant + other.additive_constant)
            else:
                # Constant + witness
                return Fr_ct(
                    other.additive_constant + self.additive_constant,
                    other.multiplicative_constant,
                    other.witness_index,
                    other.builder,
                )
        else:
            # Witness + constant
            if other.multiplicative_constant == Fr(0):
                return Fr_ct(
                    other.additive_constant + self.additive_constant,
                    self.multiplicative_constant,
                    self.witness_index,
                    self.builder,
                )
            # Witnesses with the same underlying witness index are being added. No need to do anything in the circuit yet, just update constants
            elif other.witness_index == self.witness_index:
                return Fr_ct(
                    self.additive_constant + other.additive_constant,
                    self.multiplicative_constant + other.multiplicative_constant,
                    self.witness_index,
                    self.builder,
                )
            else:
                # 2 different witnesses, need to perform the full computation
                new_value = (
                    self.multiplicative_constant
                    * self.builder.get_variable_value(self.witness_index)
                    + self.additive_constant
                    + other.multiplicative_constant
                    * self.builder.get_variable_value(other.witness_index)
                    + other.additive_constant
                )
                new_index = self.builder.add_variable(new_value)

                self.builder.create_poly_gate(
                    CircuitRow(
                        Fr(0),
                        self.multiplicative_constant,
                        other.multiplicative_constant,
                        Fr(-1),
                        self.additive_constant + other.additive_constant,
                    ),
                    WitnessIndexRow(self.witness_index, other.witness_index, new_index),
                )
                return Fr_ct(Fr(0), Fr(1), new_index, self.builder)

    def __mul__(self, other):
        """Multiply two elements together"""
        if self.multiplicative_constant == Fr(0):
            if other.multiplicative_constant == Fr(0):
                # Multiplying two constants
                return Fr_ct(self.additive_constant * other.additive_constant)
            else:
                # Constant * witness
                return Fr_ct(
                    Fr(0),
                    self.additive_constant * other.multiplicative_constant,
                    other.witness_index,
                    other.builder,
                )
        else:
            # Witness * constant
            if other.multiplicative_constant == Fr(0):
                return Fr_ct(
                    Fr(0),
                    other.additive_constant * self.multiplicative_constant,
                    self.witness_index,
                    self.builder,
                )
            # Witnesses with the same underlying witness index are being multiplied.
            elif other.witness_index == self.witness_index:
                # Create a multiplication gate for squaring
                base = (
                    self.multiplicative_constant
                    * self.builder.get_variable_value(self.witness_index)
                    + self.additive_constant
                )
                new_value = base * base
                new_index = self.builder.add_variable(new_value)
                self.builder.create_multiplication_gate(
                    self.witness_index, self.witness_index, new_index
                )
                return Fr_ct(Fr(0), Fr(1), new_index, self.builder)
            else:
                # 2 different witnesses, need to perform the full computation
                new_value = (
                    self.multiplicative_constant
                    * self.builder.get_variable_value(self.witness_index)
                    + self.additive_constant
                ) * (
                    other.multiplicative_constant
                    * self.builder.get_variable_value(other.witness_index)
                    + other.additive_constant
                )
                new_index = self.builder.add_variable(new_value)

                self.builder.create_multiplication_gate(
                    self.witness_index, other.witness_index, new_index
                )
                return Fr_ct(Fr(0), Fr(1), new_index, self.builder)

    def __neg__(self):
        """Negate an element"""
        return Fr_ct(
            -self.additive_constant,
            -self.multiplicative_constant,
            self.witness_index,
            self.builder,
        )

    def __sub__(self, other):
        """Subtract two elements (a - b)"""
        # Subtraction is equivalent to adding the negation: a - b = a + (-b)
        return self + (-other)


class TestFF_CT_Methods(unittest.TestCase):
    def test_add_constants(self):
        a = Fr(1)
        b = Fr(1)
        a_ct = Fr_ct(a)
        b_ct = Fr_ct(b)
        for i in range(20):
            (a, b) = (b, a + b)
            (a_ct, b_ct) = (b_ct, a_ct + b_ct)
        self.assertTrue(a_ct.additive_constant == a)
        self.assertTrue(b_ct.additive_constant == b)

    def test_add_variables(self):
        cb = CircuitBuilder()
        a = Fr(1)
        b = Fr(1)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        for i in range(20):
            (a, b) = (b, a + b)
            (a_ct, b_ct) = (b_ct, a_ct + b_ct)

        a_ct = a_ct.normalize()
        b_ct = b_ct.normalize()

        self.assertTrue(cb.get_variable_value(a_ct.witness_index) == a)
        self.assertTrue(cb.get_variable_value(b_ct.witness_index) == b)

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())
        cb.print_circuit()

    def test_multiply_constants(self):
        a = Fr(3)
        b = Fr(5)
        a_ct = Fr_ct(a)
        b_ct = Fr_ct(b)
        result_ct = a_ct * b_ct
        self.assertTrue(result_ct.additive_constant == Fr(15))

    def test_multiply_variables(self):
        cb = CircuitBuilder()
        a = Fr(3)
        b = Fr(5)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        result_ct = a_ct * b_ct
        result_ct = result_ct.normalize()
        self.assertTrue(cb.get_variable_value(result_ct.witness_index) == a * b)
        result_ct.constrain(a * b)
        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

    def test_negate_constant(self):
        a = Fr(7)
        a_ct = Fr_ct(a)
        neg_a_ct = -a_ct
        self.assertTrue(neg_a_ct.additive_constant == Fr(-7))

    def test_negate_variable(self):
        cb = CircuitBuilder()
        a = Fr(7)
        a_ct = Fr_ct.create_witness(cb, a)
        neg_a_ct = -a_ct
        neg_a_ct = neg_a_ct.normalize()
        self.assertTrue(cb.get_variable_value(neg_a_ct.witness_index) == Fr(-7))

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

    def test_square_variable(self):
        cb = CircuitBuilder()
        a = Fr(7)
        a_ct = Fr_ct.create_witness(cb, a)
        result_ct = a_ct * a_ct
        result_ct = result_ct.normalize()
        self.assertTrue(cb.get_variable_value(result_ct.witness_index) == a * a)

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

    def test_subtract_constants(self):
        """Test subtraction of constants."""
        a = Fr(10)
        b = Fr(3)
        a_ct = Fr_ct(a)
        b_ct = Fr_ct(b)
        result_ct = a_ct - b_ct
        self.assertTrue(result_ct.additive_constant == Fr(7))

    def test_subtract_variables(self):
        """Test subtraction of circuit variables."""
        cb = CircuitBuilder()
        a = Fr(10)
        b = Fr(3)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        result_ct = a_ct - b_ct
        result_ct = result_ct.normalize()
        self.assertTrue(cb.get_variable_value(result_ct.witness_index) == a - b)

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

    def test_subtract_constant_from_variable(self):
        """Test subtracting a constant from a variable."""
        cb = CircuitBuilder()
        a = Fr(10)
        b = Fr(3)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct(b)
        result_ct = a_ct - b_ct
        result_ct = result_ct.normalize()
        self.assertTrue(cb.get_variable_value(result_ct.witness_index) == a - b)

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

    def test_subtract_variable_from_constant(self):
        """Test subtracting a variable from a constant."""
        cb = CircuitBuilder()
        a = Fr(10)
        b = Fr(3)
        a_ct = Fr_ct(a)
        b_ct = Fr_ct.create_witness(cb, b)
        result_ct = a_ct - b_ct
        result_ct = result_ct.normalize()
        self.assertTrue(cb.get_variable_value(result_ct.witness_index) == a - b)

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

    def test_subtract_same_variable(self):
        """Test subtracting a variable from itself (should be zero)."""
        cb = CircuitBuilder()
        a = Fr(7)
        a_ct = Fr_ct.create_witness(cb, a)
        result_ct = a_ct - a_ct
        result_ct = result_ct.normalize()
        # Check that all circuit constraints are satisfied
        self.assertTrue(result_ct.get_value() == Fr(0))

    def test_complex_subtraction_arithmetic(self):
        """Test complex arithmetic involving subtraction."""
        cb = CircuitBuilder()

        # Create witnesses: a = 10, b = 3, c = 2
        a = Fr(10)
        b = Fr(3)
        c = Fr(2)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        c_ct = Fr_ct.create_witness(cb, c)

        # Compute: result = (a - b) * c = (10-3) * 2 = 7 * 2 = 14
        sub_result = a_ct - b_ct
        final_result = sub_result * c_ct
        final_result = final_result.normalize()

        expected = (a - b) * c
        self.assertTrue(cb.get_variable_value(final_result.witness_index) == expected)

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

        # Print the circuit to see the gates
        print("\nComplex subtraction arithmetic circuit:")
        cb.print_circuit()

    def test_complex_arithmetic(self):
        """Test a complex arithmetic expression to verify circuit constraints work together."""
        cb = CircuitBuilder()

        # Create witnesses: a = 3, b = 5, c = 2
        a = Fr(3)
        b = Fr(5)
        c = Fr(2)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        c_ct = Fr_ct.create_witness(cb, c)

        # Compute: result = (a * b) + (-c) = 3*5 + (-2) = 15 - 2 = 13
        mult_result = a_ct * b_ct
        neg_c = -c_ct
        final_result = mult_result + neg_c
        final_result = final_result.normalize()

        expected = a * b + (-c)
        self.assertTrue(cb.get_variable_value(final_result.witness_index) == expected)

        # Check that all circuit constraints are satisfied
        self.assertTrue(cb.check_circuit())

        # Print the circuit to see the gates
        print("\nComplex arithmetic circuit:")
        cb.print_circuit()

    def test_circuit_constraint_failure(self):
        """Test that circuit constraint checking fails when there's an inconsistency."""
        cb = CircuitBuilder()

        # Create a witness
        a = Fr(3)
        a_ct = Fr_ct.create_witness(cb, a)

        # Manually create an inconsistent gate by setting wrong output value
        # This should make the circuit constraint check fail
        wrong_output = cb.add_variable(Fr(999))  # Wrong value
        cb.create_multiplication_gate(
            a_ct.witness_index, a_ct.witness_index, wrong_output
        )

        # The circuit should fail constraint checking
        self.assertFalse(cb.check_circuit())

        # Fix the circuit by setting the correct output value
        cb.variables[wrong_output] = a * a
        self.assertTrue(cb.check_circuit())


if __name__ == "__main__":
    unittest.main()
