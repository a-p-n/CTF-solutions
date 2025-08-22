# This file contains the description of polynomials that are used in the proof
from collections import namedtuple

NUMBER_OF_POLYNOMIALS = 22
NUMBER_OF_COMMITTED_POLYNOMIALS = 17
NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS = 13
NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS = 3
DERIVED_POLYNOMIALS = 1
POLYNOMIALS_WITH_SHIFT = 4
AllPolynomials = namedtuple(
    "AllPolynomials",
    [
        "lagrange_first",
        "lagrange_last",
        "q_m",
        "q_l",
        "q_r",
        "q_o",
        "q_c",
        "id_l",
        "id_r",
        "id_o",
        "sigma_l",
        "sigma_r",
        "sigma_o",
        "w_l",
        "w_r",
        "w_o",
        "permutation",
        "permutation_shift",
        "w_l_shift",
        "w_r_shift",
        "w_o_shift",
        "zeta_powers",  # has to be last since we are not sending evaluation to the verifier
    ],
    defaults=[[] for _ in range(NUMBER_OF_POLYNOMIALS)],
)
