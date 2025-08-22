from prover import Verifier
import socketserver
from flag import flag
import logging

HOST = "0.0.0.0"
PORT = 1337

hello_string = """Ok, no more logup. That was the only problem last time. Surely you can't break this one. If you can forge a proof for an impossible statement, I'll give you the flag:
Just send the proof in hex (nc can't handle >4096 so I recommend sending via python)
"""
prompt = ">"
standard_two_plus_two_two_by_two_vk = b""
impossible_two_plus_two_two_by_two_vk = b""
PROOF_SIZE = 7368 >> 1
with open("standard_two_plus_two_two_by_two.vk", "r") as f:
    standard_two_plus_two_two_by_two_vk = bytes.fromhex(f.read())

with open("impossible_two_plus_two_two_by_two.vk", "r") as f:
    impossible_two_plus_two_two_by_two_vk = bytes.fromhex(f.read())


class CheckHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):

        self.request.sendall((hello_string + prompt).encode())
        while True:
            try:
                data = b""
                while len(data) < (PROOF_SIZE * 2):
                    data += self.request.recv(128)
                proof_data = bytes.fromhex(data.strip().decode())
                if len(proof_data) < PROOF_SIZE:
                    self.request.sendall(
                        ("PROOF is too short, try again\n" + prompt).encode()
                    )
                    continue
                if (
                    proof_data[: len(standard_two_plus_two_two_by_two_vk)]
                    == standard_two_plus_two_two_by_two_vk
                ):
                    self.request.sendall(
                        b"Checking standard two plus two two by two proof:\n"
                    )
                    verifier = Verifier(proof_data)
                    result = verifier.verify(standard_two_plus_two_two_by_two_vk)
                    if result:
                        self.request.sendall(b"Success! But you don't get the flag\n")
                    else:
                        self.request.sendall(b"Verification failed. Surprising\n")
                elif (
                    proof_data[: len(impossible_two_plus_two_two_by_two_vk)]
                    == impossible_two_plus_two_two_by_two_vk
                ):
                    self.request.sendall(
                        b"Checking impossible two plus two two by two proof:\n"
                    )
                    verifier = Verifier(proof_data)
                    result = verifier.verify(impossible_two_plus_two_two_by_two_vk)
                    if result:
                        self.request.sendall(f"Success! {flag}\n".encode())
                    else:
                        self.request.sendall(b"Verification failed\n")
                else:
                    self.request.sendall(
                        b"No idea what this circuit is (unknown verification key)\n"
                    )
                self.request.sendall(prompt.encode())
                return

            except ValueError:
                logging.error("Conversion problem or bad data")
                self.request.sendall(
                    ("Malformed data (did you send hex?)\n" + prompt).encode()
                )
                return
            except ConnectionResetError:
                logging.error("Connection reset by client")
                return
            except UnicodeDecodeError:
                logging.error("Client sent weird data")
                return
            except AttributeError:
                logging.error("Malformed command")
                self.request.sendall(("Malformed command\n" + prompt).encode())
                return

            except Exception as e:
                self.request.sendall((f"Encountered exception {e}").encode())
                return


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
        datefmt="%m-%d %H:%M",
        filename="server.log",
        filemode="w",
    )
    server = socketserver.ThreadingTCPServer(
        (HOST, PORT), CheckHandler, bind_and_activate=False
    )
    server.request_queue_size = 2000
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()
    logging.info(f"Started listenning on {HOST}:{PORT}")
    server.serve_forever()
