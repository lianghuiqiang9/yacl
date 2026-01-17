#include <iostream>
#include <chrono>
#include <iomanip>

#include "hesm2_kpir/kpir.h"

using namespace examples::kpir;
int main() {
    uint32_t logN = 5;              // database size 2^logN
    uint32_t logX = 6;              // key bits
    uint32_t logY = 6;              // key bits
    uint32_t logL = 32;             // label bits

    uint32_t s = 1 << (logN / 2);               // s = sqrt N
    uint32_t t = ((1 << logN) + s - 1) / s;     // t = sqrt N

    std::cout << "--- KPIR Configuration ---\n"
              << "Database Size (n): " << (1<<logN) << "\n"
              << "Query Range: [0, " << (1<<logX) << ")\n"
              << "Optimization (s, t): (" << s << ", " << t << ")\n" << std::endl;

    InitializeConfig();
    auto ec_group = yacl::crypto::EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");

    examples::hesm2::PrivateKey sk(std::move(ec_group));
    auto pk = &(sk.GetPublicKey());
    Database db;
    db.Random(logN, logY, logL);
    db.GetCoeffs(pk->GetEcGroup()->GetOrder());

    for (int i = 0; i < 10; ++i){
        yacl::math::MPInt k = yacl::math::MPInt::RandomLtN(yacl::math::MPInt(2).Pow(logX)); //db.Y[i]; //yacl::math::MPInt::RandomLtN(yacl::math::MPInt(2).Pow(logX));
    
        auto queryState = PolyKPIR::Query(*pk, k, s);
        auto query = queryState.cipherX;
    
        auto response = PolyKPIR::Answer(*pk, query, db, s);
   
        auto result = PolyKPIR::Recover(sk, response, queryState.plainX);
    
        auto expectResult = db.GetVal(k);
    

        std::cout << "Query Keyword: " << k 
                    << " \tRecovered Label: " << result 
                    << " \tExpected Label: " << expectResult <<std::endl;
    }

    return 0;
}