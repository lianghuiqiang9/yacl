
# How to build and run

bazel build //yacl/...

cd examples

bazel clean --expunge

bazel build --linkopt=-ldl //hesm2_kpir:kpir_example

./bazel-bin/hesm2_kpir/kpir_example

# Algorithms:
Input:
Client: x
Server: (Y,L) = {(y_0, l_0), (y_1, l_1), ..., (y_{n-1}, l_{n-1})}
Output:
Client: l_i, if x == y_i, otherwise 0.

1. Setup
Compute the coffes = Interpolate(Y, L), satified that 
    coffes * [1, y_i, y_i^2, ..., y_i^{n-1}] = l_i

2. Query
Compute the X = [x, x^2, ..., x^s], where s * t = n.

3. Answer
Compute response[0] = coffes[0] + coffes[1, 2, ..., s] * [x, x^2, ...,x^s]
        response[1] = coffes[s + 1,s + 2, ...,2s] * [x, x^2, ...,x^s]
        ...
        response[t-2]= coffes[(t-2)s + 1,(t-2)s + 2, ...,(t-1)s] * [x, x^2, ...,x^s]
        response[t-1]= coffes[(t-1)s + 1,(t-1)s + 2, ...,ts-1] * [x, x^2, ...,x^{s-1}]

4. Recover
Compute result = response[0] + response[1] * x^s + ... + response[t-1] *{x^s}^{t-1}
Decrypt result if reasult < 2^log2L, otherwise return 0. 

# Next work
1. CRT packing for long label.