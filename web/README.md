The key handling tilder.run runs: the key signer at keys.tilder.run (`signer/`,
which holds the device key, the wrapped root and the directory key, and signs
only what it is asked for by name), and the console's side of it: the wrapped
root, the sealed directory, adding a device. It is published to be
read and checked against `vectors/`; the console's interface around it is not,
so it does not build on its own.
