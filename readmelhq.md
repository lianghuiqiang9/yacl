
# run
1. bazel build //yacl/...
2. bazel test //yacl/...
3. cd examples
4. bazel build --linkopt=-ldl //hesm2:sm2_example
5. ./bazel-bin/hesm2/sm2_example
6. bazel build //psi/cpp:ecdh_psi_main --verbose_failures
7. ./bazel-bin/psi/cpp/ecdh_psi_main