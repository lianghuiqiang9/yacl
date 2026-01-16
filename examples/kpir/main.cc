#include <iostream>
#include <chrono>
#include <iomanip>

#include "kpir/kpir.h"

using namespace examples::kpir;

int main() {
    uint32_t logN = 5;              // 数据库大小 2^10
    uint32_t logX = 6;              // 索引长度 bits
    uint32_t logY = 6;              // 索引长度 bits
    uint32_t logL = 32;             // 标签长度 bits

    uint32_t s = 1 << (logN / 2);               // s = sqrt N
    uint32_t t = ((1 << logN) + s - 1) / s;     // t = sqrt N

    std::cout << "--- KPIR Configuration ---\n"
              << "Database Size (n): " << (1<<logN) << "\n"
              << "Query Range: [0, " << (1<<logX) << ")\n"
              << "Optimization (s, t): (" << s << ", " << t << ")\n" << std::endl;

    auto sk = PolyKPIR::Setup();
    auto pk = &(sk->GetPublicKey());
    Database db;
    db.Random(logN, logY, logL);
    db.GetCoeffs(pk->GetEcGroup()->GetOrder());
    yacl::math::MPInt k = yacl::math::MPInt::RandomLtN(yacl::math::MPInt(2).Pow(logX)); //db.Y[4]; //yacl::math::MPInt::RandomLtN(yacl::math::MPInt(2).Pow(logX));
    
    auto queryState = PolyKPIR::Query(*pk, k, s);
    auto query = queryState.cipherX;
    
    auto response = PolyKPIR::Answer(*pk, query, db, s);
   
    auto result = PolyKPIR::Recover(*sk, response, queryState.plainX);
    
    bool isCorrect = PolyKPIR::Verify(k, db, result);
    
    std::cout << "\n--- Final Result ---" << std::endl;
    std::cout << "Query Keyword: " << k << std::endl;
    std::cout << "Recovered Label: " << result << std::endl;
    std::cout << "Verification: " << (isCorrect ? "SUCCESS ✅" : "FAILED ❌, not found") << std::endl;

    return 0;
}