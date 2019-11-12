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

#include <josepp/jws.hpp>
#include <josepp/tools.hpp>

namespace jose {

static const std::string bearer_hdr("bearer ");

jws::jws(jose::alg alg, const std::string &data, sp_hdr hdr, sp_claims cl, const std::string &sig)
	: _alg(alg)
	, _data(data)
    , _hdr(hdr)
    , _claims(cl)
	, _sig(sig) {

}

bool jws::verify(sp_crypto c, verify_cb v) {
	if (!c) {
		throw std::runtime_error("uninitialized crypto");
	}

	if (c->alg() != _alg) {
		throw std::runtime_error("invalid crypto alg");
	}

	if (!c->verify(_data, _sig)) {
		return false;
	}

	if (v) {
		return v(_claims);
	}

	return true;
}

sp_jws jws::parse(const std::string &full_bearer, bool is_bearer) {
    std::string raw;

    if(is_bearer) {
        bool has_bearer = true;
        for (size_t i = 0; i < bearer_hdr.length(); i++) {
            if (bearer_hdr[i] != tolower(full_bearer[i])) {
                has_bearer = false;
            }
        }

        if (is_bearer && !has_bearer) {
            throw std::invalid_argument("Bearer header is invalid");
        }

        raw = full_bearer.substr(bearer_hdr.length());
    }else{
        raw = full_bearer;
    }

	std::vector<std::string> tokens;
	tokens = tokenize(raw, '.');

	if (tokens.size() != 3) {
		throw std::runtime_error("Bearer is invalid");
	}

	Json::Value hdr;

	try {
		hdr = unmarshal_b64(tokens[0]);
	} catch (...) {
		throw;
	}

	if (!hdr.isMember("typ") || !hdr.isMember("alg")) {
		throw std::runtime_error("Invalid JWT header");
	}

	jose::alg alg = crypto::str2alg(hdr["alg"].asString());
	if (alg >= jose::alg::UNKNOWN) {
		throw std::runtime_error("Invalid alg");
	}

    sp_hdr h;
    sp_claims cl;

	try {
        h = std::make_shared<class hdr>(tokens[0], true);
        cl = std::make_shared<class claims>(tokens[1], true);
	} catch (...) {
		throw;
	}

	std::string d = tokens[0];
	d += ".";
	d += tokens[1];

	jws *j;

	try {
		j = new jws(alg, d, h, cl, tokens[2]);
	} catch (...) {
		throw;
	}

	return sp_jws(j);
}

std::string jws::sign(const std::string &data, sp_crypto c) {
	return c->sign(data);
}

std::string jws::sign_claims(class hdr& h, class claims &cl, sp_crypto c) {
	std::string out;

	h.set().alg(crypto::alg2str(c->alg()));
	out = h.b64();
	out += ".";
	out += cl.b64();

	std::string sig;
	sig = jws::sign(out, c);
	out += ".";
	out += sig;

	return out;
}

std::string jws::sign_bearer(class hdr& h, class claims &cl, sp_crypto c) {
	std::string bearer("Bearer ");
	bearer += jws::sign_claims(h, cl, c);
	return bearer;
}

std::string jws::sign_claims(class claims &cl, sp_crypto c) {
    class hdr h;
    return sign_claims(h, cl, c);
}
std::string jws::sign_bearer(class claims &cl, sp_crypto c) {
    class hdr h;
    return sign_bearer(h, cl, c);
}

std::vector<std::string> jws::tokenize(const std::string &text, char sep) {
	std::vector<std::string> tokens;
	std::size_t start = 0;
	std::size_t end = 0;

	while ((end = text.find(sep, start)) != std::string::npos) {
		tokens.push_back(text.substr(start, end - start));
		start = end + 1;
	}

	tokens.push_back(text.substr(start));

	return tokens;
}

} // namespace jose
