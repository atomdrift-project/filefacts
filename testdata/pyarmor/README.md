The runtime, container and plaintext fixtures are synthetic. AES ciphertext was
generated independently with OpenSSL AES-128-CTR, counter 2. No specimen executes.

`marshal-container.bin` contains a normal CPython 3.14 marshal code object.
`nested-container.bin` contains manually encoded CPython 3.11 root and nested
code objects with PyArmor metadata trailers and encrypted instruction regions.
`nested-normalized.pyc` is the independently constructed expected result.
