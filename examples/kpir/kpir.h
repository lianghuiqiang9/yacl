#pragma once

#include "hesm2/ahesm2.h"

namespace examples::kpir {

using namespace examples::hesm2;

class Database {
public:
    std::vector<yacl::math::MPInt> Y;
    std::vector<yacl::math::MPInt> L;
    std::vector<yacl::math::MPInt> Coeffs;

    void Random(uint32_t logN, uint32_t logY,uint32_t logL);
    void GetCoeffs(const yacl::math::MPInt& order);
    void MultiplyByLinearFactor(std::vector<yacl::math::MPInt>& coeffs, 
                                const yacl::math::MPInt& a, 
                                const yacl::math::MPInt& order);
};

class PolyKPIR {
public:

    static std::unique_ptr<examples::hesm2::PrivateKey> Setup();

    struct QueryState {
        std::vector<Ciphertext> cipherX;
        std::vector<yacl::math::MPInt> plainX;
    };
    static QueryState Query(const PublicKey& pk, 
                            const yacl::math::MPInt& x, 
                            uint32_t s);

    static std::vector<Ciphertext> Answer(const PublicKey& pk, 
                                          const std::vector<Ciphertext>& cipherX, 
                                          const Database& db, 
                                          uint32_t s);

    static yacl::math::MPInt Recover(const PrivateKey& sk, 
                                     const std::vector<Ciphertext>& response,
                                     const std::vector<yacl::math::MPInt>& plainX);

    static bool Verify(const yacl::math::MPInt& x, 
                        const Database& db, 
                        const yacl::math::MPInt& result);

};

} // namespace examples::hesm2_kpir