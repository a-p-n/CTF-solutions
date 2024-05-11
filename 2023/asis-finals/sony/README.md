The challenges uses a McEliece cryptosystem with parameters (n, k, w) = (256, 128, 16). These are very small parameters - using the syndrome decoder estimator we see that it takes \sim 2^{38} effort to solve the corresponding ISD instance using Prange's algorithm:

>>> from sd_estimator.estimator import sd_estimate_display
>>> sd_estimate_display(n=256,k=128,w=16)
Computing estimates			|################################| 8/8
=========================================================================
Complexity estimation to solve the (256,128,16) syndrome decoding problem
=========================================================================
The following table states bit complexity estimates of the corresponding algorithms including an approximation of the polynomial factors inherent to the algorithm.
The quantum estimate gives a very optimistic estimation of the cost for a quantum aided attack with a circuit of limitted depth (should be understood as a lowerbound).
+----------------+---------------+---------+
|                |    estimate   | quantum |
+----------------+------+--------+---------+
| algorithm      | time | memory |    time |
+----------------+------+--------+---------+
| Prange         | 37.9 |   15.3 |   25.9  |
| Stern          | 29.2 |   20.0 |    --   |
| Dumer          | 29.9 |   20.3 |    --   |
| Ball Collision | 30.2 |   20.0 |    --   |
| BJMM (MMT)     | 29.9 |   18.6 |    --   |
| BJMM-pdw       | 30.2 |   18.4 |    --   |
| May-Ozerov     | 29.1 |   17.7 |    --   |
| Both-May       | 29.5 |   18.4 |    --   |
+----------------+------+--------+---------+
In Sage, a slightly better algorithm called the Lee-Brickell algorithm is implemented, which decodes the syndrome correctly, giving the flag in a few minutes.