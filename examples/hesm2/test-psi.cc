// Copyright ...

#include <iostream>
#include <unordered_set>

#include "hesm2/ahesm2.h"
#include "hesm2/config.h"
#include "hesm2/private_key.h"

#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"

using yacl::crypto::EcGroupFactory;
using namespace examples::hesm2;
using Pair = std::pair<yacl::math::MPInt, yacl::math::MPInt>;

// -----------------------------------------------------------------------------
// Generate n distinct pairs (y_i, l_i) with y_i ∈ [0, yrange), l_i ∈ [0, lrange)
// -----------------------------------------------------------------------------
std::vector<Pair> GenUniqueY(
    uint32_t n,
    const yacl::math::MPInt& yrange,
    const yacl::math::MPInt& lrange)
{
    if (yacl::math::MPInt(n) >= yrange) {
        throw std::invalid_argument("n must be < yrange");
    }

    std::unordered_set<yacl::math::MPInt> used;
    std::vector<Pair> Y;
    Y.reserve(n);

    while (Y.size() < n) {
        auto y = yacl::math::MPInt::RandomLtN(yrange);
        if (!used.insert(y).second) continue;

        auto l = yacl::math::MPInt::RandomLtN(lrange);
        Y.emplace_back(y, l);
    }

    return Y;
}

// -----------------------------------------------------------------------------
// Print vector of pairs
// -----------------------------------------------------------------------------
void PrintY(const std::vector<Pair>& Y) {
    for (size_t i = 0; i < Y.size(); ++i) {
        std::cout << "Y[" << i << "] = ("
                  << Y[i].first
                  << ", 0x" << Y[i].second.ToHexString()
                  << ")\n";
    }
}

// -----------------------------------------------------------------------------
// Generate n MPInt values of form (1 || r_i)
// High bit = 1 at position `llen`, lower bits random
// -----------------------------------------------------------------------------
std::vector<yacl::math::MPInt> GenOneConcatRandom(
    uint32_t n,
    uint32_t llen,
    const yacl::math::MPInt& lrange)
{
    std::vector<yacl::math::MPInt> result;
    result.reserve(n);

    //auto two = yacl::math::MPInt(2);
    yacl::math::MPInt high_bit = yacl::math::MPInt(2).Pow(llen);  // 1 << llen

    for (size_t i = 0; i < n; ++i) {
        yacl::math::MPInt ri = yacl::math::MPInt::RandomLtN(lrange);
        yacl::math::MPInt val = high_bit | ri;    // set highest bit
        result.push_back(val);
    }

    return result;
}

// -----------------------------------------------------------------------------
// Print MPInt vector
// -----------------------------------------------------------------------------
void PrintMPIntV(const std::vector<yacl::math::MPInt>& vec) {
    for (size_t i = 0; i < vec.size(); ++i) {
        std::cout << "Vec[" << i << "] = 0x"
                  << vec[i].ToHexString() << "\n";
    }
}

// Compute the communication size of a ciphertext and optionally print points
uint64_t CiphertextSize(const PublicKey &public_key,
                              const examples::hesm2::Ciphertext &cipher) {
    // Get affine points from the EC group inside public key
    auto affc1 = public_key.GetEcGroup()->GetAffinePoint(cipher.GetC1());
    auto affc2 = public_key.GetEcGroup()->GetAffinePoint(cipher.GetC2());

    uint64_t comm_c1 = affc1.GetSerializeLength();
    uint64_t comm_c2 = affc2.GetSerializeLength();

    uint64_t total_comm = comm_c1 + comm_c2;


    return total_comm;
}

// -----------------------------------------------------------------------------
// Main: HE-based PSI example
// -----------------------------------------------------------------------------
int main() {
    // -------------------------------------------------------------------------
    // Step 0: data and parameter initialization
    // -------------------------------------------------------------------------
    uint32_t xlen = 5;

    auto xrange = yacl::math::MPInt(2).Pow(xlen);
    //xrange.PowInplace(xlen);

    uint32_t log2n = 4;   // log2n < xlen
    uint32_t n = 1 << log2n;

    uint32_t ylen = xlen;
    yacl::math::MPInt yrange = xrange;

    uint32_t llen = 32;
    auto lrange = yacl::math::MPInt(2).Pow(llen);
    //lrange.PowInplace(llen);

    std::cout << "log2n=" << log2n
              << ", n=" << n
              << ", xlen=" << xlen
              << ", ylen=" << ylen
              << ", llen=" << llen
              << ", xrange=[0, " << xrange
              << "), yrange=[0, " << xrange
              << "), lrange=[0, " << lrange << ")\n";

    // Generate X and Y
    yacl::math::MPInt x = yacl::math::MPInt::RandomLtN(xrange);
    auto yVec = GenUniqueY(n, yrange, lrange);

    std::cout << "x = " << x << "\n";
    //PrintY(yVec);

    // -------------------------------------------------------------------------
    // Step 1: create keys and encrypt -x
    // -------------------------------------------------------------------------
    InitializeConfig();

    auto ec_group =
        EcGroupFactory::Instance().Create("sm2", yacl::ArgLib = "openssl");

    if (!ec_group) {
        std::cerr << "Failed to create SM2 curve\n";
        return 1;
    }

    PrivateKey private_key(std::move(ec_group));
    const auto& public_key = private_key.GetPublicKey();

    yacl::math::MPInt xneg = -x;
    auto start = std::chrono::high_resolution_clock::now();
    auto c_xneg = Encrypt(xneg, public_key);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Step 1, client computation time: "
              << duration.count() << " ms" << std::endl;
    
    auto client_comm = CiphertextSize(public_key, c_xneg);

    std::cout << "Step 1, client_comm: " << std::fixed 
                                         << std::setprecision(2)
                                         << client_comm / 1024.0
                                         << " KB" << std::endl;


    // -------------------------------------------------------------------------
    // Step 2: Server computes:
    //   (1||r_i)*(y_i − x) + (1||l_i)
    // -------------------------------------------------------------------------
    
    // Offline: compute r_i' * y_i + (1||l_i)
    start = std::chrono::high_resolution_clock::now();
    auto rVec = GenOneConcatRandom(n, llen, lrange);
    //PrintMPIntV(rVec);

    //auto two  = yacl::math::MPInt(2);
    yacl::math::MPInt one_L = yacl::math::MPInt(2).Pow(llen);       // 1<<llen
    //yacl::math::MPInt one_L_plus = two.Pow(llen+1);
    //std::cout << "one_bit_pow_llen = " << one_L.ToHexString() << "\n";

    std::vector<examples::hesm2::Ciphertext> response;
    response.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        //yacl::math::MPInt val = (one_L | yVec[i].second);
        auto val = yVec[i].second + rVec[i] * yVec[i].first;
        auto c_val = RawEncrypt(val, public_key);
        response.push_back(c_val);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Step 2, server offline computation time: "
              << duration.count() << " ms" << std::endl;

    // Online: add r_i * (-x)
    start = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < n; ++i) {
        auto c_r_mul_xneg = HMul(c_xneg, rVec[i], public_key);
        response[i] = HAdd(response[i], c_r_mul_xneg, public_key);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Step 2, server online computation time: "
              << duration.count() << " ms" << std::endl;

    auto server_comm = 0;
    for (uint32_t i = 0; i < n; ++i) {
      server_comm = server_comm + CiphertextSize(public_key, response[i]);
    }
    std::cout << "Step 2, server_comm: " << std::fixed 
                                         << std::setprecision(2)
                                         << server_comm / 1024.0
                                         << " KB" << std::endl;
    // -------------------------------------------------------------------------
    // Step 3: Client decrypts
    // -------------------------------------------------------------------------
    start = std::chrono::high_resolution_clock::now();
    std::vector<examples::hesm2::DecryptResult> answer;
    answer.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        answer.push_back(RawDecrypt(response[i], private_key));
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Step 3, client decrypts computation time: "
              << duration.count() << " ms" << std::endl;

    auto actual_ans = yacl::math::MPInt(-1);
    for (uint32_t i = 0; i < n; ++i) {
        auto val = answer[i].m;
        //std::cout << "answer[" << i << "] = 0x" << val.ToHexString() << ", success=" << answer[i].success << "\n";

        if (val >= 0 && val < one_L && answer[i].success) {
            actual_ans = val;
        }
    }

    std::cout << "x = " << x << ", actual_ans = " << actual_ans << "\n";

    // -------------------------------------------------------------------------
    // Step 4: Plaintext check
    // -------------------------------------------------------------------------
    auto expect_ans = yacl::math::MPInt(-1);

    for (uint32_t i = 0; i < n; ++i) {
        if (x == yVec[i].first) {
            expect_ans = yVec[i].second;
            break;
        }
    }

    std::cout << "x = " << x
              << ", expect_ans = " << expect_ans << "\n";

    return 0;
}
