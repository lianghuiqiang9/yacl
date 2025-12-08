#include <iostream>
#include <chrono>

#include "hesm2/ahesm2.h"
#include "hesm2/config.h"
#include "hesm2/private_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

using namespace std;
using namespace std::chrono;
using yacl::crypto::EcGroupFactory;
using namespace examples::hesm2;


int main() {
  // 参数配置并读取预计算表
  InitializeConfig();

  auto start_total = high_resolution_clock::now();

  // ======================
  //  生成SM2椭圆曲线群
  // ======================
  auto ts = high_resolution_clock::now();
  auto ec_group =
      EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");
  if (!ec_group) {
    std::cerr << "Failed to create SM2 curve using OpenSSL" << std::endl;
    return 1;
  }
  auto te = high_resolution_clock::now();
  cout << "[TIME] Create SM2 group = "
       << duration_cast<milliseconds>(te - ts).count() << " ms\n";

  // ======================
  // 生成密钥
  // ======================
  ts = high_resolution_clock::now();
  PrivateKey private_key(std::move(ec_group));
  const auto& public_key = private_key.GetPublicKey();
  te = high_resolution_clock::now();
  cout << "[TIME] KeyGen = "
       << duration_cast<milliseconds>(te - ts).count() << " ms\n";

  // 明文
  auto m1 = yacl::math::MPInt(-100);
  auto m2 = yacl::math::MPInt(-6);
  cout<<"Mmax: "<<Mmax<<", m1: "<<m1<<", m2: "<<m2<<endl;
  // ======================
  //  加密
  // ======================
  ts = high_resolution_clock::now();
  auto c1 = Encrypt(m1, public_key);
  te = high_resolution_clock::now();
  cout << "[TIME] Encrypt(m1) = "
       << duration_cast<microseconds>(te - ts).count() << " us\n";

  ts = high_resolution_clock::now();
  auto c2 = Encrypt(m2, public_key);
  te = high_resolution_clock::now();
  cout << "[TIME] Encrypt(m2) = "
       << duration_cast<microseconds>(te - ts).count() << " us\n";

  

  // ======================
  //  同态运算
  // ======================
  ts = high_resolution_clock::now();
  auto c3 = HMul(c1, m2, public_key);
  te = high_resolution_clock::now();
  cout << "[TIME] HMul(c1, m2) = "
       << duration_cast<microseconds>(te - ts).count() << " us\n";

  ts = high_resolution_clock::now();
  auto c4 = HAdd(c1, c2, public_key);
  te = high_resolution_clock::now();
  cout << "[TIME] HAdd(c1, c2) = "
       << duration_cast<microseconds>(te - ts).count() << " us\n";

  // ======================
  //  解密
  // ======================
  ts = high_resolution_clock::now();
  auto res3 = Decrypt(c3, private_key);
  te = high_resolution_clock::now();
  cout << "[TIME] Decrypt(c3) = "
       << duration_cast<microseconds>(te - ts).count() << " us\n";

  ts = high_resolution_clock::now();
  auto res4 = ParDecrypt(c4, private_key);
  te = high_resolution_clock::now();
  cout << "[TIME] ParDecrypt(c4) = "
       << duration_cast<microseconds>(te - ts).count() << " us\n";

  auto end_total = high_resolution_clock::now();
  cout << "[TIME] Total = "
       << duration_cast<milliseconds>(end_total - start_total).count()
       << " ms\n";

  // 打印结果
  cout << "\n=== Results ===\n";
  cout << "res3 = " << res3.m << " success=" << res3.success << endl;
  cout << "res4 = " << res4.m << " success=" << res4.success << endl;

  return 0;
}
