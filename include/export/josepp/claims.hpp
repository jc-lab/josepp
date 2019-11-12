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

#pragma once

#include <json/json.h>

#include <memory>
#include <string>

namespace jose {

#if defined(_MSC_VER) && (_MSC_VER < 1700)
    #define final

    typedef std::shared_ptr<class claims> sp_claims;
    typedef std::unique_ptr<class claims> up_claims;
#else
    using sp_claims = std::shared_ptr<class claims>;
    using up_claims = std::unique_ptr<class claims>;
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

/**
 * \brief
 */
class claims final {
private:
	class has {
	public:
		explicit has(Json::Value *c) : _claims(c) {}
	public:
		bool any(const std::string &key) { return _claims->isMember(key); }
		bool iss() { return any("iss"); }
		bool sub() { return any("sub"); }
		bool aud() { return any("aud"); }
		bool exp() { return any("exp"); }
		bool nbf() { return any("nbf"); }
		bool iat() { return any("iat"); }
		bool jti() { return any("jti"); }
	private:
		Json::Value *_claims;
	};

	class check {
	public:
		explicit check(Json::Value *c) : _claims(c) {}
	public:
		bool any(const std::string &key, const std::string &value) {
			std::string s = _claims->operator[](key).asString();
			return s == value;
		}
		bool iss(const std::string &value) { return any("iss", value); }
		bool sub(const std::string &value) { return any("sub", value); }
		bool aud(const std::string &value) { return any("aud", value); }
		bool exp(const std::string &value) { return any("exp", value); }
		bool nbf(const std::string &value) { return any("nbf", value); }
		bool iat(const std::string &value) { return any("iat", value); }
		bool jti(const std::string &value) { return any("jti", value); }
	private:
		Json::Value *_claims;
	};

	class del {
	public:
		explicit del(Json::Value *c) : _claims(c) {}
	public:
		void any(const std::string &key) { _claims->removeMember(key); }
		void iss() { any("iss"); }
		void sub() { any("sub"); }
		void aud() { any("aud"); }
		void exp() { any("exp"); }
		void nbf() { any("nbf"); }
		void iat() { any("nbf"); }
		void jti() { any("jti"); }
	private:
		Json::Value *_claims;
	};


	class get {
	public:
		explicit get(Json::Value *c) : _claims(c) {}
	public:
		std::string any(const std::string &key) {
			return _claims->operator[](key).asString();
		}
		const Json::Value *json(const std::string &key) {
			return &_claims->operator[](key);
		}
		std::string iss() { return any("iss"); }
		std::string sub() { return any("sub"); }
		std::string aud() { return any("aud"); }
		std::string exp() { return any("exp"); }
		std::string nbf() { return any("nbf"); }
		std::string iat() { return any("iat"); }
		std::string jti() { return any("jti"); }
	private:
		Json::Value *_claims;
	};

	class set {
	public:
		explicit set(Json::Value *c) : _claims(c) {}
	public:
		void any(const std::string &key, const std::string &value);
		void iss(const std::string &value) { any("iss", value); }
		void sub(const std::string &value) { any("sub", value); }
		void aud(const std::string &value) { any("aud", value); }
		void exp(const std::string &value) { any("exp", value); }
		void nbf(const std::string &value) { any("nbf", value); }
		void iat(const std::string &value) { any("iat", value); }
		void jti(const std::string &value) { any("jti", value); }

	private:
		Json::Value *_claims;
	};
public:
	/**
	 * \brief
	 */
	claims();

	/**
	 * \brief
	 *
	 * \param d
	 */
	explicit claims(const std::string &d, bool b64 = false);

	/**
	 * \brief
	 *
	 * \param key
	 * \param value
	 *
	 * \return
	 */
	class claims::set &set() { return _set; }

	/**
	 * \brief
	 *
	 * \param key
	 *
	 * \return
	 */
	class claims::has &has() { return _has; }

	/**
	 * \brief
	 *
	 * \param key
	 *
	 * \return
	 */
	class claims::del &del() { return _del; }

	/**
	 * \brief
	 *
	 * \param key
	 *
	 * \return
	 */
	class claims::get &get() { return _get; }

	class claims::check &check() { return _check; }

	std::string b64();

#if !(defined(_MSC_VER) && (_MSC_VER < 1700))
public:
	template <typename... _Args>
	static sp_claims make_shared(_Args&&... __args) {
		return std::make_shared<class claims>(__args...);
	}
#endif // !(defined(_MSC_VER) && (_MSC_VER < 1700))

private:
	Json::Value _claims;

	class set   _set;
	class get   _get;
	class has   _has;
	class del   _del;
	class check _check;
};

} // namespace jose
