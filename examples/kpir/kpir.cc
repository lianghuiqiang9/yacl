#include "kpir/kpir.h"
#include <unordered_set>

namespace examples::kpir {

void Database::Random(uint32_t logN, uint32_t logY,uint32_t logL) {
    if (logN > logY) {
        throw std::runtime_error("Error: logN cannot be greater than logY. "
                                 "Not enough unique values available for Y.");
    }

    std::unordered_set<yacl::math::MPInt> used;
    uint32_t n = 1<<logN;
    auto yLen = yacl::math::MPInt(2).Pow(logY);
    auto lLen = yacl::math::MPInt(2).Pow(logL);

    Y.reserve(n);
    L.reserve(n);

    while (Y.size() < n) {
        auto y = yacl::math::MPInt::RandomLtN(yLen);
        if (!used.insert(y).second) continue;

        auto l = yacl::math::MPInt::RandomLtN(lLen);
        Y.emplace_back(y);
        L.emplace_back(l);
    }
}


void Database::MultiplyByLinearFactor(
    std::vector<yacl::math::MPInt>& coeffs,
    const yacl::math::MPInt& a,
    const yacl::math::MPInt& order)
{
    size_t n = coeffs.size();
    
    std::vector<yacl::math::MPInt> newCoeffs(n + 1, yacl::math::MPInt::_0_);
    
    // (c0 + c1*x + ... + c_{n-1}*x^{n-1}) * (x - a)
    for (size_t i = 0; i < n; ++i) {
        newCoeffs[i + 1] = (newCoeffs[i + 1] + coeffs[i]) % order;
        
        yacl::math::MPInt negA = (order - a) % order;  // -a mod order
        newCoeffs[i] = (newCoeffs[i] + coeffs[i] * negA) % order;
    }
    
    coeffs = std::move(newCoeffs);
}

void Database::GetCoeffs(const yacl::math::MPInt& order) {
    size_t n = Y.size();

    std::vector<std::vector<yacl::math::MPInt>> dividedDiffs(n, 
        std::vector<yacl::math::MPInt>(n, yacl::math::MPInt::_0_));
    
    // f[y_i] = l_i
    for (size_t i = 0; i < n; ++i) {
        dividedDiffs[i][0] = L[i] % order;
    }
    
    // 
    for (size_t j = 1; j < n; ++j) {
        for (size_t i = 0; i < n - j; ++i) {
            yacl::math::MPInt numerator = 
                (dividedDiffs[i + 1][j - 1] - dividedDiffs[i][j - 1]) % order;
            yacl::math::MPInt denominator = 
                (Y[i + j] - Y[i]) % order;
            
            yacl::math::MPInt denomInv = denominator.InvertMod(order);
            dividedDiffs[i][j] = (numerator * denomInv) % order;
        }
    }
    
    // c0 + c1*(x-y0) + c2*(x-y0)*(x-y1) + ...
    Coeffs.assign(n, yacl::math::MPInt::_0_);
    // c0 = f[y0]
    Coeffs[0] = dividedDiffs[0][0];

    std::vector<yacl::math::MPInt> currentPoly = { yacl::math::MPInt::_1_ };
    
    for (size_t j = 1; j < n; ++j) {
        MultiplyByLinearFactor(currentPoly, Y[j - 1], order);
        
        yacl::math::MPInt cj = dividedDiffs[0][j];
        for (size_t k = 0; k < currentPoly.size(); ++k) {
            yacl::math::MPInt term = (currentPoly[k] * cj) % order;
            Coeffs[k] = (Coeffs[k] + term) % order;
        }
    }

}

std::unique_ptr<examples::hesm2::PrivateKey> PolyKPIR::Setup() {
    examples::hesm2::InitializeConfig();
    auto ec_group = yacl::crypto::EcGroupFactory::Instance().Create(
        "sm2", yacl::ArgLib = "openssl");

    return std::make_unique<examples::hesm2::PrivateKey>(std::move(ec_group));
}

PolyKPIR::QueryState PolyKPIR::Query(const PublicKey& pk, const yacl::math::MPInt& x, uint32_t s) {
    auto order = pk.GetEcGroup()->GetOrder();
    
    std::vector<yacl::math::MPInt> plainX;
    plainX.reserve(s);
    
    yacl::math::MPInt current_x_pow = x % order;
    for (uint32_t i = 0; i < s; ++i) {
        plainX.push_back(current_x_pow);
        if (i < s - 1) {
            current_x_pow = (current_x_pow * x) % order;
        }
    }
    std::vector<Ciphertext> cipherX;
    for (const auto& val : plainX) {
        cipherX.push_back(RawEncrypt(val, pk));
    }
    return {cipherX, plainX};
}

std::vector<Ciphertext> PolyKPIR::Answer(const PublicKey& pk, 
                                         const std::vector<Ciphertext>& cipherX, 
                                         const Database& db, 
                                         uint32_t s) {
    auto order = pk.GetEcGroup()->GetOrder();
    uint32_t n = db.Y.size();
    uint32_t t = (n + s - 1) / s;

    std::vector<Ciphertext> response;
    response.reserve(t);

    for (uint32_t i = 0; i < t; ++i) {
        auto temp = HMul(cipherX[0], db.Coeffs[s*i + 1], pk);
        for (uint32_t j = 1; j < s; ++j) {
            uint32_t idx = s*i + j + 1;
            if (idx >= n) break;
            temp = HAdd(temp, HMul(cipherX[j], db.Coeffs[idx], pk), pk);
        }
        response.push_back(temp);
    }
    // add a0
    response[0] = HAdd(response[0], RawEncrypt(db.Coeffs[0], pk), pk);
    return response;
}

/*
yacl::math::MPInt PolyKPIR::Recover(const PrivateKey& sk, 
                                    const std::vector<Ciphertext>& response,
                                    const std::vector<yacl::math::MPInt>& plainX) {
    const auto& pk = sk.GetPublicKey();
    auto order = pk.GetEcGroup()->GetOrder();
    auto Result = response[0];
    auto xPowS = plainX.back(); // x^s
                                        
    for (size_t i = 1; i < response.size(); ++i) {
        //  response[i] * (x^s)^i
        auto term = HMul(response[i], xPowS, pk);
        Result = HAdd(Result, term, pk);
        if (i < response.size() - 1) {
            xPowS = (xPowS * plainX.back()) % order;
        }
    }

    auto plainResult = Decrypt(Result, sk);
    return plainResult.m;
}
*/

yacl::math::MPInt PolyKPIR::Recover(const PrivateKey& sk, 
                                    const std::vector<Ciphertext>& response,
                                    const std::vector<yacl::math::MPInt>& plainX) {
    if (response.empty()) return yacl::math::MPInt::_0_;
    
    const auto& pk = sk.GetPublicKey();
    const auto& xPowS = plainX.back(); // x^s
    
    // Result = response[n-1]
    auto Result = response.back();
    
    for (int i = static_cast<int>(response.size()) - 2; i >= 0; --i) {
        // Result = response[i] + Result * x^s
        auto shifted = HMul(Result, xPowS, pk);
        Result = HAdd(response[i], shifted, pk);
    }

    auto plainResult = Decrypt(Result, sk);
    return plainResult.m;
}

bool PolyKPIR::Verify(const yacl::math::MPInt& x, const Database& db, const yacl::math::MPInt& result) {
    for (size_t i = 0; i < db.Y.size(); ++i) {
        if (x == db.Y[i]) return result == db.L[i];
    }
    return result == yacl::math::MPInt(-1);
}


} // namespace examples::hesm2_kpir