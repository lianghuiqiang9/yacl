// Copyright 2024 Guowei Ling.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>

#include "hesm2/ahesm2.h"
#include "hesm2/config.h"
#include "hesm2/private_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

using yacl::crypto::EcGroupFactory;
using namespace examples::hesm2;

int main() {
    auto ec_group = EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
    if (!ec_group) {
        std::cerr << "Failed to create EC group" << std::endl;
        return 1;
    }

    const int N = 10000; // 测试循环次数

    yacl::math::MPInt k = ec_group->GetOrder() - 1;
    // yacl::math::MPInt::RandomLtN(ec_group->GetOrder(), &k);
    std::cout<<"k: "<<k<< ", k.BitCount() = " << k.BitCount()<<std::endl;
    auto point = ec_group->GetGenerator();
    
    
    auto n_sub_1G = ec_group->MulBase(k);
    auto nG = ec_group->Add(point,n_sub_1G);
    auto affnG = ec_group->GetAffinePoint(nG);
    std::cout<<"affnG: "<<affnG<<std::endl;
    auto m2 = yacl::math::MPInt(0);
    auto m2G = ec_group->MulBase(m2);
    std::cout<<"ecgroup->PointEqual(nG, m2G): "<<ec_group->PointEqual(nG, m2G)<<std::endl;







    // 1️⃣ 测试 MulBase (生成元标量乘)
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < N; ++i) {
        auto r = ec_group->MulBase(k);
        (void)r;
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::cout << "MulBase " << N << " times: "
              << std::chrono::duration<double, std::milli>(end-start).count()
              << " ms" << std::endl;

    // 2️⃣ 测试 Add (点加法)
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < N; ++i) {
        auto r = ec_group->Add(point, point);
        (void)r;
    }
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Add " << N << " times: "
              << std::chrono::duration<double, std::milli>(end-start).count()
              << " ms" << std::endl;

    // 3️⃣ 测试 Mul (任意点标量乘)
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < N; ++i) {
        auto r = ec_group->Mul(point, k);
        (void)r;
    }
    end = std::chrono::high_resolution_clock::now();
    std::cout << "Mul " << N << " times: "
              << std::chrono::duration<double, std::milli>(end-start).count()
              << " ms" << std::endl;

    return 0;
}