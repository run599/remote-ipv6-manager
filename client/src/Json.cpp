#include "Json.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace r6m {

namespace {

const int kMaxDepth = 64;   // 递归深度上限：防止对端用深层嵌套把栈打爆

struct Parser {
    const std::string& s;
    size_t i = 0;
    int depth = 0;
    std::string err;

    explicit Parser(const std::string& src) : s(src) {}

    bool fail(const char* why) {
        char buf[160];
        snprintf(buf, sizeof(buf), "%s (位置 %zu)", why, i);
        err = buf;
        return false;
    }

    void skipWs() {
        while (i < s.size()) {
            char c = s[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { i++; continue; }
            break;
        }
    }

    bool literal(const char* lit) {
        size_t n = strlen(lit);
        if (s.compare(i, n, lit) != 0) return fail("非法字面量");
        i += n;
        return true;
    }

    // UTF-8 编码一个码点
    static void appendUtf8(std::string& out, unsigned int cp) {
        if (cp <= 0x7F) {
            out += (char)cp;
        } else if (cp <= 0x7FF) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        } else if (cp <= 0xFFFF) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }

    bool hex4(unsigned int& out) {
        if (i + 4 > s.size()) return fail("\\u 后不足 4 位");
        out = 0;
        for (int k = 0; k < 4; k++) {
            char c = s[i + k];
            unsigned int d;
            if (c >= '0' && c <= '9') d = (unsigned int)(c - '0');
            else if (c >= 'a' && c <= 'f') d = (unsigned int)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = (unsigned int)(c - 'A' + 10);
            else return fail("\\u 后非十六进制");
            out = (out << 4) | d;
        }
        i += 4;
        return true;
    }

    bool parseString(std::string& out) {
        if (i >= s.size() || s[i] != '"') return fail("期望字符串起始引号");
        i++;
        out.clear();
        while (true) {
            if (i >= s.size()) return fail("字符串未闭合");
            unsigned char c = (unsigned char)s[i++];
            if (c == '"') return true;
            if (c < 0x20) return fail("字符串内含未转义控制字符");
            if (c != '\\') { out += (char)c; continue; }
            if (i >= s.size()) return fail("转义符未闭合");
            char e = s[i++];
            switch (e) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'u': {
                    unsigned int cp = 0;
                    if (!hex4(cp)) return false;
                    // 代理对：D800-DBFF 高代理后必须跟 DC00-DFFF 低代理
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                            i += 2;
                            unsigned int lo = 0;
                            if (!hex4(lo)) return false;
                            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            } else {
                                cp = 0xFFFD; // 非法代理：替换字符，不产出坏字节
                            }
                        } else {
                            cp = 0xFFFD;
                        }
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        cp = 0xFFFD;
                    }
                    appendUtf8(out, cp);
                    break;
                }
                default: return fail("未知转义序列");
            }
        }
    }

    bool parseNumber(Json& out) {
        size_t start = i;
        if (i < s.size() && (s[i] == '-' || s[i] == '+')) i++;
        bool any = false;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') { i++; any = true; }
        if (i < s.size() && s[i] == '.') {
            i++;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') { i++; any = true; }
        }
        if (any && i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
            i++;
            if (i < s.size() && (s[i] == '-' || s[i] == '+')) i++;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') i++;
        }
        if (!any) return fail("非法数字");
        out.type = Json::Number;
        out.number = strtod(s.substr(start, i - start).c_str(), nullptr);
        return true;
    }

    bool parseValue(Json& out) {
        if (++depth > kMaxDepth) return fail("嵌套过深");
        skipWs();
        if (i >= s.size()) return fail("意外的输入结束");
        char c = s[i];
        bool ok = false;
        if (c == '{') {
            ok = parseObject(out);
        } else if (c == '[') {
            ok = parseArray(out);
        } else if (c == '"') {
            out.type = Json::String;
            ok = parseString(out.text);
        } else if (c == 't') {
            ok = literal("true");
            out.type = Json::Bool; out.boolean = true;
        } else if (c == 'f') {
            ok = literal("false");
            out.type = Json::Bool; out.boolean = false;
        } else if (c == 'n') {
            ok = literal("null");
            out.type = Json::Null;
        } else {
            ok = parseNumber(out);
        }
        depth--;
        return ok;
    }

    bool parseObject(Json& out) {
        out.type = Json::Object;
        i++; // '{'
        skipWs();
        if (i < s.size() && s[i] == '}') { i++; return true; }
        while (true) {
            skipWs();
            std::string key;
            if (!parseString(key)) return false;
            skipWs();
            if (i >= s.size() || s[i] != ':') return fail("对象缺冒号");
            i++;
            Json v;
            if (!parseValue(v)) return false;
            out.fields[key] = v;
            skipWs();
            if (i >= s.size()) return fail("对象未闭合");
            if (s[i] == ',') { i++; continue; }
            if (s[i] == '}') { i++; return true; }
            return fail("对象内期望 , 或 }");
        }
    }

    bool parseArray(Json& out) {
        out.type = Json::Array;
        i++; // '['
        skipWs();
        if (i < s.size() && s[i] == ']') { i++; return true; }
        while (true) {
            Json v;
            if (!parseValue(v)) return false;
            out.items.push_back(v);
            skipWs();
            if (i >= s.size()) return fail("数组未闭合");
            if (s[i] == ',') { i++; continue; }
            if (s[i] == ']') { i++; return true; }
            return fail("数组内期望 , 或 ]");
        }
    }
};

void dumpTo(const Json& j, std::string& out) {
    char buf[64];
    switch (j.type) {
        case Json::Null:   out += "null"; break;
        case Json::Bool:   out += j.boolean ? "true" : "false"; break;
        case Json::Number:
            snprintf(buf, sizeof(buf), "%.17g", j.number);
            out += buf;
            break;
        case Json::String: out += '"'; out += jsonEscape(j.text); out += '"'; break;
        case Json::Array:
            out += '[';
            for (size_t k = 0; k < j.items.size(); k++) {
                if (k) out += ',';
                dumpTo(j.items[k], out);
            }
            out += ']';
            break;
        case Json::Object:
            out += '{';
            for (std::map<std::string, Json>::const_iterator it = j.fields.begin(); it != j.fields.end(); ++it) {
                if (it != j.fields.begin()) out += ',';
                out += '"'; out += jsonEscape(it->first); out += "\":";
                dumpTo(it->second, out);
            }
            out += '}';
            break;
    }
}

} // namespace

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (size_t k = 0; k < s.size(); k++) {
        unsigned char c = (unsigned char)s[k];
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;   // UTF-8 字节直通
                }
        }
    }
    return out;
}

const Json* Json::find(const std::string& key) const {
    if (type != Object) return nullptr;
    std::map<std::string, Json>::const_iterator it = fields.find(key);
    return it == fields.end() ? nullptr : &it->second;
}

std::string Json::getString(const std::string& key, const std::string& def) const {
    const Json* v = find(key);
    return (v && v->isString()) ? v->text : def;
}

double Json::getNumber(const std::string& key, double def) const {
    const Json* v = find(key);
    return (v && v->isNumber()) ? v->number : def;
}

bool Json::getBool(const std::string& key, bool def) const {
    const Json* v = find(key);
    return (v && v->isBool()) ? v->boolean : def;
}

std::string Json::dump() const {
    std::string out;
    dumpTo(*this, out);
    return out;
}

Json Json::makeObject() { Json j; j.type = Object; return j; }
Json Json::makeArray()  { Json j; j.type = Array;  return j; }
Json Json::makeString(const std::string& s) { Json j; j.type = String; j.text = s; return j; }
Json Json::makeNumber(double d) { Json j; j.type = Number; j.number = d; return j; }
Json Json::makeBool(bool b) { Json j; j.type = Bool; j.boolean = b; return j; }

bool Json::parse(const std::string& in, Json& out, std::string* err) {
    Parser p(in);
    out = Json();
    if (!p.parseValue(out)) {
        if (err) *err = p.err;
        return false;
    }
    p.skipWs();
    if (p.i != in.size()) {
        if (err) *err = "末尾存在多余字符";
        return false;
    }
    return true;
}

} // namespace r6m
