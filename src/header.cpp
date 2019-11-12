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

#include <josepp/header.hpp>
#include <josepp/b64.hpp>
#include <josepp/tools.hpp>
#include <josepp/crypto.hpp>

namespace jose {

void hdr::set::any(const std::string &key, const std::string &value)
{
    if (key.empty() || value.empty())
        throw std::invalid_argument("Invalid params");

    _claims->operator[](key) = value;
}

void hdr::set::arr(const std::string &key, const std::list<std::string> &value) {
    Json::Value jarr;

    if (key.empty())
        throw std::invalid_argument("Invalid params");

    for(auto it = value.cbegin(); it != value.cend(); it++) {
        jarr.append(*it);
    }

    _claims->operator[](key) = jarr;
}

hdr::hdr()
    : _claims()
    , _set(&_claims)
    , _get(&_claims)
    , _has(&_claims)
    , _del(&_claims)
    , _check(&_claims)
{}

hdr::hdr(const std::string &d, bool b64)
	: hdr()
{
    if (b64) {
        std::string decoded = b64::decode_uri(d);

        std::stringstream(decoded) >> _claims;
    } else {
        std::stringstream(d) >> _claims;
    }

	if (!_claims.isMember("typ") || !_claims["typ"].isString()) {
		throw std::runtime_error("stream does not have valid \"typ\" field");
	}

	if (!_claims.isMember("alg") || !_claims["alg"].isString()) {
		throw std::runtime_error("stream does not have valid \"alg\" field");
	}

	if (jose::crypto::str2alg(_claims["alg"].asString()) == jose::alg::UNKNOWN) {
		throw std::runtime_error("invalid \"alg\" value");
	}
}

std::string hdr::b64() {
	return marshal_b64(_claims);
}

} // namespace jose
