from circuit import CircuitBuilder
from ff import Fr
import unittest
from prover import Prover, Verifier
from ff_ct import Fr_ct


def standard_two_plus_two_two_by_two_example():
    cb = CircuitBuilder()
    a = Fr_ct.create_witness(cb, Fr(2))
    b = Fr_ct.create_witness(cb, Fr(2))
    a.constrain()
    b.constrain()
    c = a + b
    d = a * b
    c.constrain(Fr(4))
    d.constrain(Fr(4))
    return cb


def impossible_two_plus_two_two_by_two_example():
    cb = CircuitBuilder()
    a = Fr_ct.create_witness(cb, Fr(2))
    b = Fr_ct.create_witness(cb, Fr(2))
    a.constrain()
    b.constrain()
    c = a + b
    d = a * b
    c.constrain(Fr(6))
    d.constrain(Fr(9))
    return cb


class TestStandard(unittest.TestCase):
    def test_standard(self):
        cb = standard_two_plus_two_two_by_two_example()
        prover = Prover(cb)
        prover.prove()
        self.assertTrue(Verifier(prover.export_proof()).verify())

    def test_broken(self):
        cb = impossible_two_plus_two_two_by_two_example()
        prover = Prover(cb)
        prover.prove()
        self.assertFalse(Verifier(prover.export_proof()).verify())


if __name__ == "__main__":
    cb = standard_two_plus_two_two_by_two_example()
    prover = Prover(cb)
    standard_two_plus_two_two_by_two_vk = prover.generate_verification_key()
    prover.prove()
    standard_two_plus_two_two_by_two_proof = prover.export_proof()
    cb = impossible_two_plus_two_two_by_two_example()
    prover = Prover(cb)
    impossible_two_plus_two_two_by_two_vk = prover.generate_verification_key()
    with open("standard_two_plus_two_two_by_two.vk", "wb") as f:
        f.write(standard_two_plus_two_two_by_two_vk.hex().encode())
    with open("impossible_two_plus_two_two_by_two.vk", "wb") as f:
        f.write(impossible_two_plus_two_two_by_two_vk.hex().encode())
    with open("standard_two_plus_two_two_by_two.proof", "w") as f:
        f.write(standard_two_plus_two_two_by_two_proof.hex())
