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

// -----------------------------------------------------------------------------
// Generate n distinct point set (y_i, l_i) with y_i ∈ [0, yrange), l_i ∈ [0, lrange)
// -----------------------------------------------------------------------------
struct PointSet {
    std::vector<yacl::math::MPInt> y;
    std::vector<yacl::math::MPInt> l;
    std::vector<yacl::math::MPInt> denom; // D_i
};

PointSet GenUniqueY(
    uint32_t n,
    const yacl::math::MPInt& yrange,
    const yacl::math::MPInt& lrange)
{
    if (yacl::math::MPInt(n) > yrange) {
        throw std::invalid_argument("n must be <= yrange");
    }

    std::unordered_set<yacl::math::MPInt> used;
    PointSet result;
    result.y.reserve(n);
    result.l.reserve(n);

    while (result.y.size() < n) {
        auto y = yacl::math::MPInt::RandomLtN(yrange);
        if (!used.insert(y).second) continue;

        auto l = yacl::math::MPInt::RandomLtN(lrange);
        result.y.emplace_back(y);
        result.l.emplace_back(l);
    }

    return result;
}

// -----------------------------------------------------------------------------
// Interpolate
// -----------------------------------------------------------------------------

void MultiplyByLinearFactor(
    std::vector<yacl::math::MPInt>& coeffs,
    const yacl::math::MPInt& a,
    const yacl::math::MPInt& Order)
{
    size_t n = coeffs.size();
    
    // 新多项式系数，次数增加1
    std::vector<yacl::math::MPInt> new_coeffs(n + 1, yacl::math::MPInt::_0_);
    
    // 多项式乘法：(c0 + c1*x + ... + c_{n-1}*x^{n-1}) * (x - a)
    for (size_t i = 0; i < n; ++i) {
        // 乘以 x：系数向右移动一位
        new_coeffs[i + 1] = (new_coeffs[i + 1] + coeffs[i]) % Order;
        
        // 乘以 -a：当前位系数乘以 -a
        yacl::math::MPInt neg_a = (Order - a) % Order;  // -a mod Order
        new_coeffs[i] = (new_coeffs[i] + coeffs[i] * neg_a) % Order;
    }
    
    coeffs = std::move(new_coeffs);
}

std::vector<yacl::math::MPInt>
GetInterpolatingPolynomialCoefficientsNewton(
    const PointSet& pts,
    const yacl::math::MPInt& Order)
{
    size_t n = pts.y.size();
    
    // 计算差商表
    std::vector<std::vector<yacl::math::MPInt>> divided_diffs(n, 
        std::vector<yacl::math::MPInt>(n, yacl::math::MPInt::_0_));
    
    // 初始化：f[y_i] = l_i
    for (size_t i = 0; i < n; ++i) {
        divided_diffs[i][0] = pts.l[i] % Order;
    }
    
    // 计算差商
    for (size_t j = 1; j < n; ++j) {
        for (size_t i = 0; i < n - j; ++i) {
            yacl::math::MPInt numerator = 
                (divided_diffs[i + 1][j - 1] - divided_diffs[i][j - 1]) % Order;
            yacl::math::MPInt denominator = 
                (pts.y[i + j] - pts.y[i]) % Order;
            
            // 分母可能为0（重复点），但根据GenUniqueY，点y是唯一的
            yacl::math::MPInt denom_inv = denominator.InvertMod(Order);
            divided_diffs[i][j] = (numerator * denom_inv) % Order;
        }
    }
    
    // 牛顿插值多项式系数：c0 + c1*(x-y0) + c2*(x-y0)*(x-y1) + ...
    std::vector<yacl::math::MPInt> coefficients(n, yacl::math::MPInt::_0_);
    
    // 初始化：c0 = f[y0]
    coefficients[0] = divided_diffs[0][0];
    
    // 临时存储当前乘积多项式的系数
    std::vector<yacl::math::MPInt> current_poly = { yacl::math::MPInt::_1_ };
    
    for (size_t j = 1; j < n; ++j) {
        // 将当前多项式乘以 (x - y_{j-1})
        MultiplyByLinearFactor(current_poly, pts.y[j - 1], Order);
        
        // 加上当前项：c_j * ∏_{k=0}^{j-1} (x - y_k)
        yacl::math::MPInt cj = divided_diffs[0][j];
        for (size_t k = 0; k < current_poly.size(); ++k) {
            yacl::math::MPInt term = (current_poly[k] * cj) % Order;
            coefficients[k] = (coefficients[k] + term) % Order;
        }
    }
    
    return coefficients;
}

yacl::math::MPInt EvaluatePolynomial(
    const std::vector<yacl::math::MPInt>& coeffs,
    const yacl::math::MPInt& x,
    const yacl::math::MPInt& Order)
{
    yacl::math::MPInt result = yacl::math::MPInt::_0_;
    
    // 从高次项到低次项，使用霍纳法则
    for (int i = coeffs.size() - 1; i >= 0; --i) {
        result = (result * x + coeffs[i]) % Order;
    }
    
    return result;
}

// -----------------------------------------------------------------------------
// 计算多项式 ∏(x - y_i) 的系数
// -----------------------------------------------------------------------------

// 递归乘法法 - 最直观的方法
std::vector<yacl::math::MPInt> ProductPolyRec(
    const std::vector<yacl::math::MPInt>& y_values,
    const yacl::math::MPInt& Order)
{
    if (y_values.empty()) {
        // 空乘积等于1
        return { yacl::math::MPInt::_1_ };
    }
    
    // 递归计算: (x - y_0) * (x - y_1) * ... * (x - y_{n-1})
    // 从最内层开始构建多项式
    std::vector<yacl::math::MPInt> result = { 
        (Order - y_values[0]) % Order,  // 常数项: -y_0
        yacl::math::MPInt::_1_          // 一次项系数: 1
    };
    
    // 依次乘以每个 (x - y_i)
    for (size_t i = 1; i < y_values.size(); ++i) {
        MultiplyByLinearFactor(result, y_values[i], Order);
    }
    
    return result;
}

// 分治法构造 ∏(x - y_i)
std::vector<yacl::math::MPInt> ProductPolyDivConq(
    const std::vector<yacl::math::MPInt>& y_values,
    size_t l, size_t r,
    const yacl::math::MPInt& Order) {

    if (l > r) return {yacl::math::MPInt::_1_};
    if (l == r) return {(Order - y_values[l]) % Order, yacl::math::MPInt::_1_};

    size_t m = (l + r) / 2;
    auto left = ProductPolyDivConq(y_values, l, m, Order);
    auto right = ProductPolyDivConq(y_values, m+1, r, Order);

    // multiply left * right
    std::vector<yacl::math::MPInt> res(left.size() + right.size() - 1, yacl::math::MPInt::_0_);
    for (size_t i = 0; i < left.size(); ++i)
        for (size_t j = 0; j < right.size(); ++j)
            res[i+j] = (res[i+j] + left[i] * right[j]) % Order;

    return res;
}


// -----------------------------------------------------------------------------
// Print vector 
// -----------------------------------------------------------------------------
void PrintPointSet(const PointSet& Y) {
    size_t n = Y.y.size();
    for (size_t i = 0; i < n; ++i) {
        std::cout << "Y[" << i << "] = ("
                  << Y.y[i]
                  << ", " << Y.l[i]
                  << ")\n";
    }
}

void PrintVhex(const std::vector<yacl::math::MPInt>& vec) {
    std::cout << "Vec[ ";
    for (size_t i = 0; i < vec.size(); ++i) {
        std::cout << vec[i].ToHexString() << " ";
    }
    std::cout << "]"<< std::endl;
}

void PrintV(const std::vector<yacl::math::MPInt>& vec) {
    std::cout << "Vec[ ";
    for (size_t i = 0; i < vec.size(); ++i) {
        std::cout << vec[i] << " ";
    }
    std::cout << "]"<< std::endl;
}

// -----------------------------------------------------------------------------
// Main: HE-based PSI example
// -----------------------------------------------------------------------------
int main() {
    // -------------------------------------------------------------------------
    // Step 0: data and parameter initialization
    // -------------------------------------------------------------------------
    // client
    uint32_t xlen = 11;
    auto xrange = yacl::math::MPInt(2).Pow(xlen);

    // server
    uint32_t log2n = 10;   // log2n < xlen
    uint32_t n = 1 << log2n;
    uint32_t ylen = xlen;
    yacl::math::MPInt yrange = xrange;
    uint32_t llen = 32;
    auto lrange = yacl::math::MPInt(2).Pow(llen);
    uint32_t s = 1 << (log2n / 2);
    uint32_t t = (n + s - 1) / s; // make sure s*t >= n 

    std::cout << "log2n=" << log2n
              << ", n=" << n
              << ", s=" << s
              << ", t=" << t
              << ", xlen=" << xlen
              << ", ylen=" << ylen
              << ", llen=" << llen
              << ", xrange=[0, " << xrange
              << "), yrange=[0, " << xrange
              << "), lrange=[0, " << lrange << ")\n";

    if (xlen < log2n){ std::cout << "xlen should large than log2n." << std::endl; return 0;}

    // Generate X and Y
    yacl::math::MPInt x = yacl::math::MPInt::RandomLtN(xrange);
    auto Y = GenUniqueY(n, yrange, lrange);

    //std::cout << "x = " << x << "\n";
    //PrintPointSet(Y);

    // -------------------------------------------------------------------------
    // Step 1: create keys and encrypt 
    // E(X) = E(x), ..., E(x^{n-1})
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

    auto Order = public_key.GetEcGroup()->GetOrder();
    //std::cout<<"Order: "<<Order<<std::endl;

    // generate x, x^2, ..., x^s
    std::vector<yacl::math::MPInt> X;
    X.reserve(s);
    X.push_back(x);
    for(uint32_t i = 1; i < s; ++i){
        auto temp = X.back() * x;
        temp = temp.Mod(Order);
        X.push_back(temp);
    }
    //PrintV(X);

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<examples::hesm2::Ciphertext> c_X;
    c_X.reserve(s);
    for (size_t i = 0; i < X.size(); ++i) {
        auto temp = RawEncrypt(X[i], public_key);
        c_X.push_back(temp);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Step 1, client setup time: "
              << duration.count() << " ms" << std::endl;
    auto client_comm = 0;
    for (size_t i = 0; i < X.size(); ++i) {
      client_comm = client_comm + CiphertextSize(public_key, c_X[i]);
    }

    std::cout << "Step 1, client_comm: " << std::fixed 
                                         << std::setprecision(2)
                                         << client_comm / 1024.0
                                         << " KB" << std::endl;


    // -------------------------------------------------------------------------
    // Step 2: Server computes:
    // offline
    //   P(y) = a_0 + a_1 * y + ... + a_{n} * y_{n}
    //   P(y_0) = l_0, ..., P(y_{n-1}) = l_{n-1}
    //   Q(y) = b_0 + b_1 * y + ... + b_{n} * y_{n}
    //   Q(y_0) = 0, ..., Q(y_{n-1}) = 0
    // online
    //   E(P(x))
    //   E(Q(x))
    // -------------------------------------------------------------------------

    start = std::chrono::high_resolution_clock::now();
    // a_0, ..., a_{n}
    auto coeffs_poly_P = GetInterpolatingPolynomialCoefficientsNewton(Y, Order);

    // b_0,..., b_{n}
    auto coeffs_poly_Q = ProductPolyDivConq(Y.y, 0, Y.y.size()-1, Order);

    std::vector<examples::hesm2::Ciphertext> c_membership_test_vec;
    c_membership_test_vec.reserve(t);

    std::vector<examples::hesm2::Ciphertext> response_vec;
    response_vec.reserve(t);

    //auto c_membership_test = RawEncrypt(coeffs_poly_Q[0], public_key);
    //auto response = RawEncrypt(coeffs_poly_P[0], public_key);

    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Step 2, server offline computation time: "
              << duration.count() << " ms" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    for (uint32_t i = 0; i < t; ++i) {
        auto temp = HMul(c_X[0], coeffs_poly_Q[s*i+1], public_key);
        for (uint32_t j = 1; j < s; ++j){
            auto v = HMul(c_X[j], coeffs_poly_Q[s*i+j+1], public_key);
            temp = HAdd(temp, v, public_key);
        }
        c_membership_test_vec.push_back(temp);
    }
    auto c_constant_coeffs_poly_Q = RawEncrypt(coeffs_poly_Q[0], public_key);
    c_membership_test_vec[0] = HAdd(c_membership_test_vec[0], c_constant_coeffs_poly_Q, public_key);

    for (uint32_t i = 0; i < t; ++i) {
        auto temp = HMul(c_X[0], coeffs_poly_P[s*i+1], public_key);
        for (uint32_t j = 1; j < s; ++j){
            if (s*i+j+1==n) continue;
            auto v = HMul(c_X[j], coeffs_poly_P[s*i+j+1], public_key);
            temp = HAdd(temp, v, public_key);
        }
        response_vec.push_back(temp);
    }  
    auto c_constant_coeffs_poly_P = RawEncrypt(coeffs_poly_P[0], public_key);
    response_vec[0] = HAdd(response_vec[0], c_constant_coeffs_poly_P, public_key);

    //std::cout<<"**"<<std::endl;
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Step 2, server online computation time: "
              << duration.count() << " ms" << std::endl;
    uint64_t server_comm = 0;
    for (uint32_t i = 0; i < response_vec.size(); ++i) {
        server_comm = server_comm + CiphertextSize(public_key, c_membership_test_vec[i]);
        server_comm = server_comm + CiphertextSize(public_key, response_vec[i]);
    }
    std::cout << "Step 2, server_comm: " << std::fixed 
                                         << std::setprecision(2)
                                         << server_comm / 1024.0
                                         << " KB" << std::endl;

    // -------------------------------------------------------------------------
    // Step 3: Client decrypts
    // -------------------------------------------------------------------------
    start = std::chrono::high_resolution_clock::now();
    auto c_membership_test = c_membership_test_vec[0]; 
    auto x_s = X.back();
    for (uint32_t i = 1; i < t; ++i) {
        auto temp = HMul(c_membership_test_vec[i], x_s, public_key);
        c_membership_test = HAdd(c_membership_test, temp, public_key);

        x_s = x_s * X.back();
        x_s = x_s.Mod(Order);
    }

    auto membership_test = ZeroCheck(c_membership_test, private_key);

    if (membership_test.m !=0) {
        std::cout << "membership_test.m: "<< membership_test.m << ", membership_test.success: "<< membership_test.success << std::endl;
        std::cout << "x is not in Y. "<<std::endl;
        
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::cout << "Step 3, client decrypts computation time: "
                  << duration.count() << " ms" << std::endl;

        return 0;
    }

    auto response = response_vec[0]; 
    x_s = X.back();
    for (uint32_t i = 1; i < t; ++i) {
        auto temp = HMul(response_vec[i], x_s, public_key);
        response = HAdd(response, temp, public_key);

        x_s = x_s * X.back();
        x_s = x_s.Mod(Order);
    }

    auto actual_ans = Decrypt(response, private_key);

    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Step 3, client decrypts computation time: "
              << duration.count() << " ms" << std::endl;

    std::cout << "x = " << x << ", actual_ans = " << actual_ans.m << "\n";
    // -------------------------------------------------------------------------
    // Step 4: Plaintext check
    // -------------------------------------------------------------------------
    auto expect_ans = yacl::math::MPInt(-1);

    for (uint32_t i = 0; i < n; ++i) {
        if (x == Y.y[i]) {
            expect_ans = Y.l[i];
            break;
        }
    }

    std::cout << "x = " << x << ", expect_ans = " << expect_ans << "\n";

    return 0;

}
