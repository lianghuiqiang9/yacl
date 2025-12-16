
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

# KeywordPIR-hesm2
0. cd examples
1. 先写在hesm2的库中，然后再迁移到psi
2. 对hesm2进行性能测试
    bazel build --linkopt=-ldl //hesm2:sm2_runtime_test
    ./bazel-bin/hesm2/sm2_runtime_test
3. 实现两个，一个是简单的，另一个是sqrt优化的

4. 测试ec-group的速度
bazel build --linkopt=-ldl //hesm2:test-ec-group-runtime && ./bazel-bin/hesm2/test-ec-group-runtime
5. 测试全域的hesm2
bazel build --linkopt=-ldl //hesm2:sm2_example && ./bazel-bin/hesm2/sm2_example

6. psi方案rE(a)+l
bazel build --linkopt=-ldl //hesm2:test-psi && ./bazel-bin/hesm2/test-psi

# KeywordPIR-hesm2-srv-poly

7. psi-poly方案

cd examples

bazel build --linkopt=-ldl //hesm2:test-poly-psi 

./bazel-bin/hesm2/test-poly-psi

# KeywordPIR-hesm2-srv-poly-sqrt

8. psi-poly-sqrt方案

cd examples

bazel build --linkopt=-ldl //hesm2:test-poly-sqrt-psi 

./bazel-bin/hesm2/test-poly-sqrt-psi