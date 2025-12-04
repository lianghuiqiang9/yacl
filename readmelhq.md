
# run
0. bazel clean --expunge
1. bazel build //yacl/...
2. bazel test //yacl/...
3. cd examples
4. bazel build --linkopt=-ldl //hesm2:sm2_example
5. ./bazel-bin/hesm2/sm2_example
6. bazel build --linkopt=-ldl //psi/cpp:ecdh_psi_main --verbose_failures
7. ./bazel-bin/psi/cpp/ecdh_psi_main --rank=0
8. ./bazel-bin/psi/cpp/ecdh_psi_main --rank=1