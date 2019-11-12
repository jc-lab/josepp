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
#include <list>

#include "types.hpp"

namespace jose {

#if defined(_MSC_VER) && (_MSC_VER < 1700)
    #define final

    typedef std::shared_ptr<class hdrs> sp_hdrs;
    typedef std::unique_ptr<class hdrs> up_hdrs;
#else
    using sp_hdr = std::shared_ptr<class hdr>;
    using up_hdr = std::unique_ptr<class hdr>;
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

/**
 * \brief
 */
    class hdr final {
    private:
        class has {
        public:
            explicit has(Json::Value *c) : _claims(c) {}
        public:
            bool any(const std::string &key) { return _claims->isMember(key); }
            bool alg() { return any("alg"); }
            bool typ() { return any("typ"); }
            bool jwu() { return any("jwu"); }
            bool jwk() { return any("jwk"); }
            bool x5u() { return any("x5u"); }
            bool x5c() { return any("x5c"); }
            bool x5t() { return any("x5t"); }
            bool x5tS256() { return any("x5t#S256"); }
            bool cty() { return any("cty"); }
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
            bool alg(const std::string &value) { return any("alg", value); }
            bool typ(const std::string &value) { return any("typ", value); }
            bool jwu(const std::string &value) { return any("jwu", value); }
            bool jwk(const std::string &value) { return any("jwk", value); }
            bool x5u(const std::string &value) { return any("x5u", value); }
            bool x5c(const std::string &value) { return any("x5c", value); }
            bool x5t(const std::string &value) { return any("x5t", value); }
            bool x5tS256(const std::string &value) { return any("x5t#S256", value); }
            bool cty(const std::string &value) { return any("cty", value); }
        private:
            Json::Value *_claims;
        };

        class del {
        public:
            explicit del(Json::Value *c) : _claims(c) {}
        public:
            void any(const std::string &key) { _claims->removeMember(key); }
            void alg() { any("alg"); }
            void typ() { any("typ"); }
            void jwu() { any("jwu"); }
            void jwk() { any("jwk"); }
            void x5u() { any("x5u"); }
            void x5c() { any("x5c"); }
            void x5t() { any("x5t"); }
            void x5tS256() { any("x5t#S256"); }
            void cty() { any("cty"); }

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
            std::list<std::string> arr(const std::string &key) {
                std::list<std::string> list;
                const Json::Value &v = _claims->operator[](key);
                if(_claims->operator[](key).isArray()) {
                    for(auto it = v.begin(); it != v.end(); it++) {
                        list.push_back(it->asString());
                    }
                }
                return list;
            }
            std::string alg() { return any("alg"); }
            std::string typ() { return any("typ"); }
            std::string jwu() { return any("jwu"); }
            std::string jwk() { return any("jwk"); }
            std::string x5u() { return any("x5u"); }
            std::list<std::string> x5c() { return arr("x5c"); }
            std::string x5t() { return any("x5t"); }
            std::string x5tS256() { return any("x5t#S256"); }
            std::string cty() { return any("cty"); }
        private:
            Json::Value *_claims;
        };

        class set {
        public:
            explicit set(Json::Value *c) : _claims(c) {}
        public:
            void any(const std::string &key, const std::string &value);
            void arr(const std::string &key, const std::list<std::string> &value);
            void alg(const std::string &value) { any("alg", value); }
            void typ(const std::string &value) { any("typ", value); }
            void jwu(const std::string &value) { any("jwu", value); }
            void jwk(const std::string &value) { any("jwk", value); }
            void x5u(const std::string &value) { any("x5u", value); }
            void x5c(const std::list<std::string> &value) { arr("x5c", value); }
            void x5t(const std::string &value) { any("x5t", value); }
            void x5tS256(const std::string &value) { any("x5t#S256", value); }
            void cty(const std::string &value) { any("cty", value); }

        private:
            Json::Value *_claims;
        };
    public:
        /**
         * \brief
         */
        hdr();

        /**
         * \brief
         *
         * \param d
         */
        explicit hdr(const std::string &d, bool b64 = false);

        /**
         * \brief
         *
         * \param key
         * \param value
         *
         * \return
         */
        class hdr::set &set() { return _set; }

        /**
         * \brief
         *
         * \param key
         *
         * \return
         */
        class hdr::has &has() { return _has; }

        /**
         * \brief
         *
         * \param key
         *
         * \return
         */
        class hdr::del &del() { return _del; }

        /**
         * \brief
         *
         * \param key
         *
         * \return
         */
        class hdr::get &get() { return _get; }

        class hdr::check &check() { return _check; }

        std::string b64();

#if !(defined(_MSC_VER) && (_MSC_VER < 1700))
    public:
        template <typename... _Args>
        static sp_hdr make_shared(_Args&&... __args) {
            return std::make_shared<class hdr>(__args...);
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
