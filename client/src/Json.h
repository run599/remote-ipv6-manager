#pragma once
// ═══════════════════════════════════════════════════════════════
// 极简 JSON —— 只为了解决一件事：把"用字符串搜索解析 JSON"全部换掉。
//
// 为什么需要它（原实现的实际故障）：
//   · StubCore 用 find("\"params\"") + 花括号计数抠 params：命令里含 '}'
//     时抠出半截 JSON；字符串里的花括号也会让计数跑偏。
//   · PluginLoader 用 "找所有 \"name\"" 建工具映射：把 inputSchema 里的
//     name 字段也当成工具名，映射被污染。
//   · syncPlugins 用 "找 command 字段里的 .py 结尾 token" 猜要下载哪些文件。
//   · 注册响应里的 agent_key 靠找引号位置提取，字段顺序一变就静默失效。
//
// 设计约束：零第三方依赖、不用异常（C++17 编译）、限制递归深度防栈溢出、
// 对非法输入返回 false 并给出错误位置，绝不静默产出半个对象。
// ═══════════════════════════════════════════════════════════════

#include <map>
#include <string>
#include <vector>

namespace r6m {

class Json {
public:
    enum Type { Null, Bool, Number, String, Array, Object };

    Type type = Null;
    bool boolean = false;
    double number = 0;
    std::string text;                  // String 的值
    std::vector<Json> items;           // Array
    std::map<std::string, Json> fields; // Object

    bool isNull()   const { return type == Null; }
    bool isBool()   const { return type == Bool; }
    bool isNumber() const { return type == Number; }
    bool isString() const { return type == String; }
    bool isArray()  const { return type == Array; }
    bool isObject() const { return type == Object; }

    // 对象取值：类型不符时返回默认值（调用方不需要先判类型）
    std::string getString(const std::string& key, const std::string& def = std::string()) const;
    double      getNumber(const std::string& key, double def = 0) const;
    bool        getBool(const std::string& key, bool def = false) const;
    // 子对象/子数组指针；不存在或类型不符返回 nullptr
    const Json* find(const std::string& key) const;

    void set(const std::string& key, const Json& v) { type = Object; fields[key] = v; }
    void push(const Json& v) { type = Array; items.push_back(v); }

    std::string dump() const;          // 紧凑序列化（UTF-8 直出）

    static Json makeObject();
    static Json makeArray();
    static Json makeString(const std::string& s);
    static Json makeNumber(double d);
    static Json makeBool(bool b);

    // 解析整段文本；尾部只允许空白。失败时返回 false，err 里带人类可读原因。
    static bool parse(const std::string& in, Json& out, std::string* err = nullptr);
};

// 把字符串转义成可嵌入 JSON 字面量的形式（含控制字符与 UTF-8 直通）
std::string jsonEscape(const std::string& s);

} // namespace r6m
