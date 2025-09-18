#include <gmpxx.h>
#include <vector>
#include <iostream>
#include <algorithm>

using namespace std;

struct SolveResult {
    bool found;
    mpz_class m;
    vector<int> bits;
    pair<int, int> pattern;
    int split_t;
};

SolveResult solve_one_case(const mpz_class& n, const mpz_class& c, const mpz_class& M, int max_bit = -1, vector<int> split_candidates = {}) {
    if (max_bit == -1) {
        int m_bits = mpz_sizeinbase(M.get_mpz_t(), 2);
        int n_bits = mpz_sizeinbase(n.get_mpz_t(), 2) - 1;
        max_bit = max(m_bits - 1, n_bits - 1);
    }

    vector<mpz_class> contrib(max_bit + 1);
    for (int i = 0; i <= max_bit; ++i) {
        unsigned long bit = mpz_tstbit(M.get_mpz_t(), i);
        int sign = (bit == 0 ? 1 : -1);
        mpz_class pow2i = mpz_class(1) << i;
        contrib[i] = mpz_class(sign) * pow2i;
    }

    mpz_class A_mod_n = (mpz_class(2) * M) % n;
    mpz_class B_mod_n = (c - (M * M % n) + n) % n;

    if (split_candidates.empty()) {
        int half = (max_bit + 1) / 2;
        split_candidates = {half, max(8, half - 32), min(max_bit - 8, half + 32)};
    }

    vector<pair<int, int>> patterns = {{4, 0}, {0, 4}, {3, 1}, {1, 3}, {2, 2}};

    SolveResult result{false};

    for (int t : split_candidates) {
        int low_size = t;
        int high_size = max_bit + 1 - t;
        if (low_size < 0 || high_size < 0) continue;

        vector<int> low_idx(low_size);
        vector<mpz_class> low_vals(low_size);
        for (int i = 0; i < low_size; ++i) {
            low_idx[i] = i;
            low_vals[i] = contrib[i];
        }

        vector<int> high_idx(high_size);
        vector<mpz_class> high_vals(high_size);
        for (int i = 0; i < high_size; ++i) {
            high_idx[i] = t + i;
            high_vals[i] = contrib[t + i];
        }

        for (auto [a, b] : patterns) {
            if (a > low_size || b > high_size) continue;

            // process_low: enumerate combos, call callback(dL, idxL_rel), stop if callback returns true
            auto process_low = [&](auto&& callback) -> void {  // callback: function<bool(const mpz_class&, const vector<int>&)>
                if (a == 0) {
                    if (callback(mpz_class(0), {})) return;
                } else if (a == 1) {
                    for (int i0 = 0; i0 < low_size; ++i0) {
                        if (callback(low_vals[i0], {i0})) return;
                    }
                } else if (a == 2) {
                    for (int i0 = 0; i0 < low_size; ++i0) {
                        for (int i1 = i0 + 1; i1 < low_size; ++i1) {
                            if (callback(low_vals[i0] + low_vals[i1], {i0, i1})) return;
                        }
                    }
                } else if (a == 3) {
                    for (int i0 = 0; i0 < low_size; ++i0) {
                        for (int i1 = i0 + 1; i1 < low_size; ++i1) {
                            for (int i2 = i1 + 1; i2 < low_size; ++i2) {
                                if (callback(low_vals[i0] + low_vals[i1] + low_vals[i2], {i0, i1, i2})) return;
                            }
                        }
                    }
                } else if (a == 4) {
                    for (int i0 = 0; i0 < low_size; ++i0) {
                        for (int i1 = i0 + 1; i1 < low_size; ++i1) {
                            for (int i2 = i1 + 1; i2 < low_size; ++i2) {
                                for (int i3 = i2 + 1; i3 < low_size; ++i3) {
                                    if (callback(low_vals[i0] + low_vals[i1] + low_vals[i2] + low_vals[i3], {i0, i1, i2, i3})) return;
                                }
                            }
                        }
                    }
                }
            };

            // Similar for process_high
            auto process_high = [&](auto&& callback) -> void {
                if (b == 0) {
                    if (callback(mpz_class(0), {})) return;
                } else if (b == 1) {
                    for (int i0 = 0; i0 < high_size; ++i0) {
                        if (callback(high_vals[i0], {i0})) return;
                    }
                } else if (b == 2) {
                    for (int i0 = 0; i0 < high_size; ++i0) {
                        for (int i1 = i0 + 1; i1 < high_size; ++i1) {
                            if (callback(high_vals[i0] + high_vals[i1], {i0, i1})) return;
                        }
                    }
                } else if (b == 3) {
                    for (int i0 = 0; i0 < high_size; ++i0) {
                        for (int i1 = i0 + 1; i1 < high_size; ++i1) {
                            for (int i2 = i1 + 1; i2 < high_size; ++i2) {
                                if (callback(high_vals[i0] + high_vals[i1] + high_vals[i2], {i0, i1, i2})) return;
                            }
                        }
                    }
                } else if (b == 4) {
                    for (int i0 = 0; i0 < high_size; ++i0) {
                        for (int i1 = i0 + 1; i1 < high_size; ++i1) {
                            for (int i2 = i1 + 1; i2 < high_size; ++i2) {
                                for (int i3 = i2 + 1; i3 < high_size; ++i3) {
                                    if (callback(high_vals[i0] + high_vals[i1] + high_vals[i2] + high_vals[i3], {i0, i1, i2, i3})) return;
                                }
                            }
                        }
                    }
                }
            };

            process_low([&](const mpz_class& dL, const vector<int>& idxL_rel) -> bool {
                mpz_class two_dL_mod_n = (mpz_class(2) * dL % n + n) % n;
                mpz_class coeff = (A_mod_n + two_dL_mod_n) % n;

                mpz_class dL_sq_mod_n = (dL * dL % n + n) % n;
                mpz_class A_dL_mod_n = (A_mod_n * dL % n + n) % n;
                mpz_class temp = (dL_sq_mod_n + A_dL_mod_n) % n;
                mpz_class const_val = (B_mod_n - temp + n) % n;

                bool found = false;
                process_high([&](const mpz_class& dH, const vector<int>& idxH_rel) -> bool {
                    mpz_class dH_sq_mod_n = (dH * dH % n + n) % n;
                    mpz_class coeff_dH_mod_n = (coeff * dH % n + n) % n;
                    mpz_class left = (dH_sq_mod_n + coeff_dH_mod_n) % n;

                    if (left == const_val) {
                        cout << "Found delta: " << dL << " " << dH << " pattern (" << a << "," << b << ") split t: " << t << endl;
                        mpz_class delta = dL + dH;
                        mpz_class m_candidate = M + delta;
                        mpz_class m_sq_mod_n = (m_candidate * m_candidate % n + n) % n;

                        if (m_sq_mod_n == c) {
                            mpz_class xor_val = m_candidate ^ M;
                            unsigned long pop = mpz_popcount(xor_val.get_mpz_t());
                            if (pop == 4) {
                                vector<int> used_bits;
                                for (int rel : idxL_rel) used_bits.push_back(low_idx[rel]);
                                for (int rel : idxH_rel) used_bits.push_back(high_idx[rel]);
                                sort(used_bits.begin(), used_bits.end());


                                result = {true, m_candidate, used_bits, {a, b}, t};
                                found = true;
                                return true;
                            }
                        }
                    }
                    return false;
                });
                return found;
            });

            if (result.found) {
                return result;
            }
        }
    }
    return result;
}

int main(int argc, char const *argv[])
{
    // Sample case
    mpz_class n, c, M;
    n = mpz_class("5130778786579458910883852670033972213803072588116359641332177299836374374225103563160645742145916166469206588314972951828881227291206301979547296716751199");
    c = mpz_class("1286135549782989317737359659416353050870323118239022417164293704578341190239857319404373893716902033617779693824962902800522656359762301958108397351850788");
    M = mpz_class("3849179278686042316623397260214400375169309143102987547383331147070673760664071551016891994874964997619397334222294495073962401383509063793308293030859269");

    cout << "Solving for:" << endl;
    cout << "n = " << n << endl;
    cout << "c = " << c << endl;
    cout << "M = " << M << endl;

    SolveResult result = solve_one_case(n, c, M);

    // if (result.found) {
    //     cout << "\nSolution found!" << endl;
    //     cout << "m = " << result.m << endl;
    //     cout << "Used bits: ";
    //     for (int bit : result.bits) {
    //         cout << bit << " ";
    //     }
    //     cout << endl;
    //     cout << "Pattern: (" << result.pattern.first << "," << result.pattern.second << ")" << endl;
    //     cout << "Split t: " << result.split_t << endl;
        
    //     // Verify solution
    //     mpz_class m_sq_mod_n = (result.m * result.m) % n;
    //     cout << "Verification: m^2 mod n = " << m_sq_mod_n << endl;
    //     cout << "Expected c = " << c << endl;
    //     cout << "Match: " << (m_sq_mod_n == c ? "YES" : "NO") << endl;
    // } else {
    //     cout << "\nNo solution found." << endl;
    // }
    
    return 0;
}