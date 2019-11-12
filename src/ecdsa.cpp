// The MIT License (MIT)
//
// Copyright (c) 2016 Artur Troian
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <openssl/err.h>

#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>

#if OPENSSL_VERSION_NUMBER < 269484032
#define OPENSSL10
#endif

namespace jose {

static std::unique_ptr<BIGNUM, decltype(&BN_free)> raw2bn(std::vector<unsigned char>& raw) {
    if(static_cast<uint8_t>(raw[0]) >= 0x80) {
        unsigned char prefix[1] = {0};
        raw.insert(raw.begin(), prefix, prefix + 1);
    }
    return std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_bin2bn((const unsigned char*)raw.data(), raw.size(), nullptr), BN_free);
}

#ifdef OPENSSL10
static std::string bn2raw(BIGNUM* bn)
#else
static std::string bn2raw(const BIGNUM* bn)
#endif
{
    std::string res;
    res.resize(BN_num_bytes(bn));
    BN_bn2bin(bn, (unsigned char*)res.data());
    if(res.size()%2 == 1 && res[0] == 0x00)
        return res.substr(1);
    return res;
}

ecdsa::ecdsa(jose::alg alg, sp_ecdsa_key key) :
	  crypto(alg)
	, _e(key)
{
	if (alg != jose::alg::ES256 && alg != jose::alg::ES384 && alg != jose::alg::ES512) {
		throw std::invalid_argument("Invalid algorithm");
	}
}

std::string ecdsa::sign(const std::string &data) {
	auto sig = std::shared_ptr<uint8_t>(new uint8_t[ECDSA_size(_e.get())], std::default_delete<uint8_t[]>());

	digest d(_hash_type, reinterpret_cast<const uint8_t *>(data.data()), data.length());

	uint32_t sig_len;

    std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>
        esig(ECDSA_do_sign((const unsigned char*)d.data(), d.size(), _e.get()), ECDSA_SIG_free);

    if(!esig) {
        throw std::runtime_error("Couldn't sign ECDSA");
    }

#ifdef OPENSSL10
    std::string ssig = bn2raw(esig->r) + bn2raw(esig->s);
#else
    const BIGNUM *bn_r;
    const BIGNUM *bn_s;
    ECDSA_SIG_get0(esig.get(), &bn_r, &bn_s);
    std::string ssig = bn2raw(bn_r) + bn2raw(bn_s);
#endif
    return b64::encode_uri((const unsigned char*)ssig.data(), ssig.size());
}

bool ecdsa::verify(const std::string &data, const std::string &sig) {
	digest d(_hash_type, reinterpret_cast<const uint8_t *>(data.data()), data.length());

	auto s = b64::decode_uri(sig.data(), sig.length());

    const unsigned char *s_ptr = s.data();
    const unsigned char *s_cur = s.data();
    std::vector<unsigned char> sig_r(s_cur, s_cur + s.size() / 2);
    s_cur += s.size() / 2;
    std::vector<unsigned char> sig_s(s_cur, s_ptr + s.size());
    auto bn_r = raw2bn(sig_r);
    auto bn_s = raw2bn(sig_s);

    // if openssl version less than 1.1
#ifdef OPENSSL10
    ECDSA_SIG esig;
	esig.r = bn_r.get();
	esig.s = bn_s.get();

	if(ECDSA_do_verify((const unsigned char*)d.data(), d.size(), &esig, _e.get()) != 1)
	    return false;
#else
    std::unique_ptr<ECDSA_SIG, void(*)(ECDSA_SIG*)> esig(ECDSA_SIG_new(), ECDSA_SIG_free);

    ECDSA_SIG_set0(esig.get(), bn_r.get(), bn_s.get());

    if(ECDSA_do_verify((const unsigned char*)d.data(), d.size(), esig.get(), _e.get()) != 1)
        return false;
#endif
    return true;
}

sp_ecdsa_key ecdsa::gen(int nid) {
	sp_ecdsa_key key = std::shared_ptr<EC_KEY>(EC_KEY_new(), ::EC_KEY_free);
	std::shared_ptr<EC_GROUP> group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(nid), ::EC_GROUP_free);
	std::shared_ptr<EC_POINT> point = std::shared_ptr<EC_POINT>(EC_POINT_new(group.get()), ::EC_POINT_free);

	if (EC_KEY_set_group(key.get(), group.get()) != 1) {
		throw std::runtime_error("Couldn't set EC KEY group");
	}

	int degree = EC_GROUP_get_degree(EC_KEY_get0_group(key.get()));
	if (degree < 160) {
		std::stringstream str;
		str << "Skip the curve [" << OBJ_nid2sn(nid) << "] (degree = " << degree << ")";
		throw std::runtime_error(str.str());
	}

	if (EC_KEY_generate_key(key.get()) != 1) {
		throw std::runtime_error("Couldn't generate EC KEY");
	}

	const BIGNUM *priv = EC_KEY_get0_private_key(key.get());

	if (EC_POINT_mul(group.get(), point.get(), priv, nullptr, nullptr, nullptr) != 1) {
		throw std::runtime_error("Couldn't generate EC PUB KEY");
	}

	if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
		throw std::runtime_error("Couldn't set EC PUB KEY");
	}

	if (EC_KEY_check_key(key.get()) != 1) {
		throw std::runtime_error("EC check failed");
	}

	return key;
}

} // namespace jose
