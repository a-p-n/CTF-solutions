FROM python:3.12-slim

RUN pip3 install pycryptodome py_ecc gmpy2
RUN groupadd -r crypto && useradd -r -u 1001 -g crypto crypto

RUN mkdir -p /home/crypto
RUN chown -R crypto /home/crypto
USER crypto

COPY circuit.py ff.py ff_ct.py flag.py gemini.py impossible_two_plus_two_two_by_two.vk instance.py kzg.py polynomial.py proof_polynomials.py prover.py relations.py ronk_srs.bin server.py shplonk.py srs_gen.py standard_two_plus_two_two_by_two.vk sumcheck.py transcript.py /home/crypto/

WORKDIR /home/crypto

EXPOSE 1337

CMD ["python3","/home/crypto/server.py"]