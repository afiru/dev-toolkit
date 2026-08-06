#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr int kSchemaVersion = 1;
constexpr char kHelperVersion[] = "0.1.0";
constexpr char kAdapter[] = "windows-native-inspector-v1";
constexpr std::size_t kMaxInputBytes = 1024 * 1024;
constexpr std::size_t kMaxStreamInfoBytes = 16 * 1024 * 1024;

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
};

struct JsonValue {
    enum class Type { Null, Boolean, Number, String, Object, Array } type = Type::Null;
    bool boolean = false;
    std::string text;
    std::map<std::string, JsonValue> object;
    std::vector<JsonValue> array;
};

void appendUtf8(std::string& output, std::uint32_t codePoint) {
    if (codePoint <= 0x7f) output.push_back(static_cast<char>(codePoint));
    else if (codePoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codePoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    } else if (codePoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codePoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    } else {
        output.push_back(static_cast<char>(0xf0 | (codePoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codePoint & 0x3f)));
    }
}

class JsonParser {
public:
    explicit JsonParser(const std::string& input) : input_(input) {}
    JsonValue parse() {
        skipWhitespace();
        JsonValue value = parseValue();
        skipWhitespace();
        if (position_ != input_.size()) throw std::runtime_error("Trailing JSON data.");
        return value;
    }

private:
    const std::string& input_;
    std::size_t position_ = 0;

    void skipWhitespace() {
        while (position_ < input_.size() && std::isspace(static_cast<unsigned char>(input_[position_]))) ++position_;
    }
    char take() {
        if (position_ >= input_.size()) throw std::runtime_error("Unexpected end of JSON.");
        return input_[position_++];
    }
    bool consume(char expected) {
        if (position_ < input_.size() && input_[position_] == expected) { ++position_; return true; }
        return false;
    }
    void expectLiteral(const char* literal) {
        while (*literal) if (take() != *literal++) throw std::runtime_error("Invalid JSON literal.");
    }
    std::uint32_t parseHex4() {
        std::uint32_t value = 0;
        for (int index = 0; index < 4; ++index) {
            const char character = take();
            value <<= 4;
            if (character >= '0' && character <= '9') value += character - '0';
            else if (character >= 'a' && character <= 'f') value += character - 'a' + 10;
            else if (character >= 'A' && character <= 'F') value += character - 'A' + 10;
            else throw std::runtime_error("Invalid JSON unicode escape.");
        }
        return value;
    }
    std::string parseString() {
        if (take() != '"') throw std::runtime_error("Expected JSON string.");
        std::string output;
        while (true) {
            const char character = take();
            if (character == '"') break;
            if (static_cast<unsigned char>(character) < 0x20) throw std::runtime_error("Invalid JSON control character.");
            if (character != '\\') { output.push_back(character); continue; }
            switch (take()) {
                case '"': output.push_back('"'); break;
                case '\\': output.push_back('\\'); break;
                case '/': output.push_back('/'); break;
                case 'b': output.push_back('\b'); break;
                case 'f': output.push_back('\f'); break;
                case 'n': output.push_back('\n'); break;
                case 'r': output.push_back('\r'); break;
                case 't': output.push_back('\t'); break;
                case 'u': {
                    std::uint32_t point = parseHex4();
                    if (point >= 0xd800 && point <= 0xdbff) {
                        if (take() != '\\' || take() != 'u') throw std::runtime_error("Invalid JSON surrogate pair.");
                        const std::uint32_t low = parseHex4();
                        if (low < 0xdc00 || low > 0xdfff) throw std::runtime_error("Invalid JSON surrogate pair.");
                        point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
                    } else if (point >= 0xdc00 && point <= 0xdfff) {
                        throw std::runtime_error("Invalid JSON surrogate pair.");
                    }
                    appendUtf8(output, point);
                    break;
                }
                default: throw std::runtime_error("Invalid JSON escape.");
            }
        }
        return output;
    }
    JsonValue parseNumber() {
        const std::size_t start = position_;
        consume('-');
        if (consume('0')) {}
        else {
            if (position_ >= input_.size() || !std::isdigit(static_cast<unsigned char>(input_[position_]))) {
                throw std::runtime_error("Invalid JSON number.");
            }
            while (position_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[position_]))) ++position_;
        }
        if (consume('.')) while (position_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[position_]))) ++position_;
        if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_; if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) ++position_;
            while (position_ < input_.size() && std::isdigit(static_cast<unsigned char>(input_[position_]))) ++position_;
        }
        JsonValue value; value.type = JsonValue::Type::Number; value.text = input_.substr(start, position_ - start); return value;
    }
    JsonValue parseObject() {
        JsonValue value; value.type = JsonValue::Type::Object;
        take(); skipWhitespace();
        if (consume('}')) return value;
        while (true) {
            skipWhitespace(); const std::string key = parseString(); skipWhitespace();
            if (!consume(':')) throw std::runtime_error("Expected JSON colon.");
            skipWhitespace();
            if (!value.object.emplace(key, parseValue()).second) throw std::runtime_error("Duplicate JSON key.");
            skipWhitespace(); if (consume('}')) break;
            if (!consume(',')) throw std::runtime_error("Expected JSON comma.");
        }
        return value;
    }
    JsonValue parseArray() {
        JsonValue value; value.type = JsonValue::Type::Array;
        take(); skipWhitespace();
        if (consume(']')) return value;
        while (true) {
            skipWhitespace(); value.array.push_back(parseValue()); skipWhitespace();
            if (consume(']')) break;
            if (!consume(',')) throw std::runtime_error("Expected JSON comma.");
        }
        return value;
    }
    JsonValue parseValue() {
        skipWhitespace();
        if (position_ >= input_.size()) throw std::runtime_error("Missing JSON value.");
        if (input_[position_] == '{') return parseObject();
        if (input_[position_] == '[') return parseArray();
        if (input_[position_] == '"') { JsonValue value; value.type = JsonValue::Type::String; value.text = parseString(); return value; }
        if (input_[position_] == 't') { expectLiteral("true"); JsonValue value; value.type = JsonValue::Type::Boolean; value.boolean = true; return value; }
        if (input_[position_] == 'f') { expectLiteral("false"); JsonValue value; value.type = JsonValue::Type::Boolean; return value; }
        if (input_[position_] == 'n') { expectLiteral("null"); return JsonValue{}; }
        return parseNumber();
    }
};

std::string escapeJson(const std::string& value) {
    std::ostringstream output;
    output << '"';
    for (const unsigned char character : value) {
        switch (character) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20) output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(character) << std::dec;
                else output << static_cast<char>(character);
        }
    }
    output << '"';
    return output.str();
}

const JsonValue& required(const JsonValue& object, const std::string& key, JsonValue::Type type) {
    if (object.type != JsonValue::Type::Object) throw std::runtime_error("Expected JSON object.");
    const auto iterator = object.object.find(key);
    if (iterator == object.object.end() || iterator->second.type != type) throw std::runtime_error("Missing or invalid field: " + key);
    return iterator->second;
}

std::wstring utf8ToWide(const std::string& value) {
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) throw std::runtime_error("Target path is not valid UTF-8.");
    std::wstring output(static_cast<std::size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), length) != length) {
        throw std::runtime_error("Target path conversion failed.");
    }
    return output;
}

std::string wideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) throw std::runtime_error("Windows text conversion failed.");
    std::string output(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), output.data(), length, nullptr, nullptr) != length) {
        throw std::runtime_error("Windows text conversion failed.");
    }
    return output;
}

std::string hexBytes(const std::uint8_t* bytes, std::size_t length) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < length; ++index) output << std::setw(2) << static_cast<unsigned>(bytes[index]);
    return output.str();
}

template<typename T>
std::string fixedHex(T value, std::size_t width) {
    std::ostringstream output;
    output << std::hex << std::nouppercase << std::setw(static_cast<int>(width)) << std::setfill('0') << value;
    return output.str();
}

class Sha256 {
public:
    Sha256() {
        if (BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed.");
        DWORD bytes = 0;
        DWORD result = 0;
        if (BCryptGetProperty(algorithm_, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&bytes), sizeof(bytes), &result, 0) < 0) {
            throw std::runtime_error("BCrypt object length query failed.");
        }
        object_.resize(bytes);
        if (BCryptCreateHash(algorithm_, &hash_, object_.data(), static_cast<ULONG>(object_.size()), nullptr, 0, 0) < 0) {
            throw std::runtime_error("BCryptCreateHash failed.");
        }
    }
    ~Sha256() {
        if (hash_) BCryptDestroyHash(hash_);
        if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
    }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    void update(const void* data, std::size_t length) {
        if (length > MAXULONG) throw std::runtime_error("Hash input is too large.");
        if (BCryptHashData(hash_, const_cast<PUCHAR>(static_cast<const UCHAR*>(data)), static_cast<ULONG>(length), 0) < 0) {
            throw std::runtime_error("BCryptHashData failed.");
        }
    }
    std::string finish() {
        std::array<std::uint8_t, 32> bytes{};
        if (BCryptFinishHash(hash_, bytes.data(), static_cast<ULONG>(bytes.size()), 0) < 0) throw std::runtime_error("BCryptFinishHash failed.");
        return hexBytes(bytes.data(), bytes.size());
    }
private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    std::vector<UCHAR> object_;
};

std::string digestTagged(const std::string& tag, const std::string& value) {
    Sha256 hash; hash.update(tag.data(), tag.size()); const char zero = '\0'; hash.update(&zero, 1); hash.update(value.data(), value.size()); return "sha256:" + hash.finish();
}

std::string sidFingerprint(PSID sid) {
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text)) throw std::runtime_error("ConvertSidToStringSidW failed.");
    const std::string utf8 = wideToUtf8(text);
    LocalFree(text);
    return digestTagged("wpb-sid-v1", utf8);
}

struct SecurityInspection {
    std::string daclFingerprint;
    bool daclProtected = false;
    std::string ownerFingerprint;
    std::string groupFingerprint;
    std::uint32_t explicitAceCount = 0;
};

SecurityInspection inspectSecurity(HANDLE file) {
    PSID owner = nullptr;
    PSID group = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD status = GetSecurityInfo(file, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, &group, &dacl, nullptr, &descriptor);
    if (status != ERROR_SUCCESS) throw std::runtime_error("GetSecurityInfo failed: " + std::to_string(status));
    SecurityInspection result;
    try {
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD descriptorRevision = 0;
        if (!GetSecurityDescriptorControl(descriptor, &control, &descriptorRevision)) throw std::runtime_error("GetSecurityDescriptorControl failed.");
        (void)descriptorRevision;
        result.daclProtected = (control & SE_DACL_PROTECTED) != 0;
        BOOL present = FALSE;
        BOOL defaulted = FALSE;
        PACL descriptorDacl = nullptr;
        if (!GetSecurityDescriptorDacl(descriptor, &present, &descriptorDacl, &defaulted)) throw std::runtime_error("GetSecurityDescriptorDacl failed.");
        std::string state = "missing";
        if (present && descriptorDacl == nullptr) state = "null";
        else if (present && descriptorDacl->AceCount == 0) state = "empty";
        else if (present) state = "present";
        LPWSTR sddl = nullptr;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr)) {
            throw std::runtime_error("DACL SDDL conversion failed.");
        }
        const std::string daclSddl = wideToUtf8(sddl);
        LocalFree(sddl);
        const DWORD daclRevision = descriptorDacl ? descriptorDacl->AclRevision : 0;
        std::string canonical = "state=" + state;
        canonical.push_back('\0');
        canonical += "protected=" + std::string(result.daclProtected ? "true" : "false");
        canonical.push_back('\0');
        canonical += "revision=" + std::to_string(daclRevision);
        canonical.push_back('\0');
        canonical += "sddl=" + daclSddl;
        result.daclFingerprint = digestTagged("wpb-dacl-v1", canonical);
        result.ownerFingerprint = sidFingerprint(owner);
        result.groupFingerprint = sidFingerprint(group);
        if (dacl) {
            for (DWORD index = 0; index < dacl->AceCount; ++index) {
                void* ace = nullptr;
                if (!GetAce(dacl, index, &ace)) throw std::runtime_error("GetAce failed.");
                const auto* header = static_cast<ACE_HEADER*>(ace);
                if ((header->AceFlags & INHERITED_ACE) == 0) ++result.explicitAceCount;
            }
        }
    } catch (...) {
        LocalFree(descriptor);
        throw;
    }
    LocalFree(descriptor);
    return result;
}

struct StreamEntry { std::wstring name; std::uint64_t size = 0; std::string hash; };
struct StreamInspection {
    std::vector<StreamEntry> entries;
    bool eaPresent = false;
    bool sparsePresent = false;
    bool unknownPresent = false;
};

std::wstring canonicalStreamName(const std::wstring& name) {
    constexpr wchar_t suffix[] = L":$DATA";
    constexpr std::size_t suffixLength = 6;
    if (name.size() > suffixLength + 1 && name.front() == L':' &&
        name.compare(name.size() - suffixLength, suffixLength, suffix) == 0) {
        return name.substr(1, name.size() - suffixLength - 1);
    }
    return name;
}

bool backupReadExact(HANDLE file, LPVOID* context, void* buffer, DWORD length, DWORD& read) {
    read = 0;
    return BackupRead(file, static_cast<LPBYTE>(buffer), length, &read, FALSE, FALSE, context) != FALSE;
}

void skipBackupBytes(HANDLE file, LPVOID* context, std::uint64_t length) {
    while (length > 0) {
        const DWORD low = static_cast<DWORD>(length & 0xffffffffULL);
        const DWORD high = static_cast<DWORD>(length >> 32);
        DWORD skippedLow = 0;
        DWORD skippedHigh = 0;
        if (!BackupSeek(file, low, high, &skippedLow, &skippedHigh, context)) throw std::runtime_error("BackupSeek failed.");
        const std::uint64_t skipped = (static_cast<std::uint64_t>(skippedHigh) << 32) | skippedLow;
        if (skipped == 0 || skipped > length) throw std::runtime_error("BackupSeek returned an invalid length.");
        length -= skipped;
    }
}

std::vector<std::pair<std::wstring, std::uint64_t>> enumerateFileStreams(HANDLE file) {
    std::size_t bufferSize = 64 * 1024;
    std::vector<std::uint8_t> buffer;
    while (true) {
        buffer.resize(bufferSize);
        if (GetFileInformationByHandleEx(file, FileStreamInfo, buffer.data(), static_cast<DWORD>(buffer.size()))) break;
        const DWORD error = GetLastError();
        if (error == ERROR_HANDLE_EOF) return {};
        if ((error != ERROR_MORE_DATA && error != ERROR_INSUFFICIENT_BUFFER) || bufferSize >= kMaxStreamInfoBytes) {
            throw std::runtime_error("FileStreamInfo inspection failed: " + std::to_string(error));
        }
        bufferSize *= 2;
    }
    std::vector<std::pair<std::wstring, std::uint64_t>> output;
    std::size_t offset = 0;
    while (offset < buffer.size()) {
        const auto* info = reinterpret_cast<const FILE_STREAM_INFO*>(buffer.data() + offset);
        const std::wstring name(info->StreamName, info->StreamNameLength / sizeof(WCHAR));
        if (name != L"::$DATA") output.emplace_back(canonicalStreamName(name), static_cast<std::uint64_t>(info->StreamSize.QuadPart));
        if (info->NextEntryOffset == 0) break;
        offset += info->NextEntryOffset;
    }
    return output;
}

StreamInspection inspectBackupStreams(HANDLE file) {
    StreamInspection result;
    LPVOID context = nullptr;
    try {
        constexpr DWORD headerSize = static_cast<DWORD>(offsetof(WIN32_STREAM_ID, cStreamName));
        while (true) {
            std::array<std::uint8_t, headerSize> headerBytes{};
            DWORD read = 0;
            if (!backupReadExact(file, &context, headerBytes.data(), headerSize, read)) throw std::runtime_error("BackupRead header failed.");
            if (read == 0) break;
            if (read != headerSize) throw std::runtime_error("BackupRead returned a partial stream header.");
            const auto* header = reinterpret_cast<const WIN32_STREAM_ID*>(headerBytes.data());
            if (header->Size.QuadPart < 0 || header->dwStreamNameSize % sizeof(WCHAR) != 0) throw std::runtime_error("Invalid backup stream header.");
            std::vector<WCHAR> nameBuffer(header->dwStreamNameSize / sizeof(WCHAR));
            if (header->dwStreamNameSize > 0) {
                if (!backupReadExact(file, &context, nameBuffer.data(), header->dwStreamNameSize, read) || read != header->dwStreamNameSize) {
                    throw std::runtime_error("BackupRead stream name failed.");
                }
            }
            const std::wstring name(nameBuffer.begin(), nameBuffer.end());
            const std::uint64_t size = static_cast<std::uint64_t>(header->Size.QuadPart);
            if (header->dwStreamId == BACKUP_ALTERNATE_DATA) {
                Sha256 hash;
                std::array<std::uint8_t, 64 * 1024> chunk{};
                std::uint64_t remaining = size;
                while (remaining > 0) {
                    const DWORD wanted = static_cast<DWORD>(std::min<std::uint64_t>(remaining, chunk.size()));
                    if (!backupReadExact(file, &context, chunk.data(), wanted, read) || read == 0) throw std::runtime_error("BackupRead ADS content failed.");
                    hash.update(chunk.data(), read);
                    remaining -= read;
                }
                result.entries.push_back({canonicalStreamName(name), size, hash.finish()});
            } else {
                if (header->dwStreamId == BACKUP_EA_DATA) result.eaPresent = true;
                else if (header->dwStreamId == BACKUP_SPARSE_BLOCK) result.sparsePresent = true;
                else if (
                    header->dwStreamId != BACKUP_DATA &&
                    header->dwStreamId != BACKUP_SECURITY_DATA &&
                    header->dwStreamId != BACKUP_LINK &&
                    header->dwStreamId != BACKUP_PROPERTY_DATA &&
                    header->dwStreamId != BACKUP_OBJECT_ID &&
                    header->dwStreamId != BACKUP_REPARSE_DATA &&
                    header->dwStreamId != BACKUP_TXFS_DATA
                ) result.unknownPresent = true;
                skipBackupBytes(file, &context, size);
            }
        }
    } catch (...) {
        DWORD ignored = 0;
        BackupRead(file, nullptr, 0, &ignored, TRUE, FALSE, &context);
        throw;
    }
    DWORD ignored = 0;
    BackupRead(file, nullptr, 0, &ignored, TRUE, FALSE, &context);
    return result;
}

void appendLe32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}
void appendLe64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}
std::string streamDigest(std::vector<StreamEntry> entries) {
    std::sort(entries.begin(), entries.end(), [](const StreamEntry& left, const StreamEntry& right) {
        return wideToUtf8(left.name) < wideToUtf8(right.name);
    });
    std::vector<std::uint8_t> canonical;
    std::string tag = "wpb-ads-v1";
    tag.push_back('\0');
    canonical.insert(canonical.end(), tag.begin(), tag.end());
    for (const StreamEntry& entry : entries) {
        const std::string name = wideToUtf8(entry.name);
        appendLe32(canonical, static_cast<std::uint32_t>(name.size()));
        canonical.insert(canonical.end(), name.begin(), name.end());
        appendLe64(canonical, entry.size);
        for (std::size_t index = 0; index < entry.hash.size(); index += 2) {
            canonical.push_back(static_cast<std::uint8_t>(std::stoul(entry.hash.substr(index, 2), nullptr, 16)));
        }
    }
    Sha256 hash; hash.update(canonical.data(), canonical.size()); return "sha256:" + hash.finish();
}

std::string streamInventoryDigest(std::vector<StreamEntry> entries) {
    std::sort(entries.begin(), entries.end(), [](const StreamEntry& left, const StreamEntry& right) {
        return wideToUtf8(left.name) < wideToUtf8(right.name);
    });
    std::vector<std::uint8_t> canonical;
    std::string tag = "wpb-ads-inventory-v1";
    tag.push_back('\0');
    canonical.insert(canonical.end(), tag.begin(), tag.end());
    for (const StreamEntry& entry : entries) {
        const std::string name = wideToUtf8(entry.name);
        appendLe32(canonical, static_cast<std::uint32_t>(name.size()));
        canonical.insert(canonical.end(), name.begin(), name.end());
        appendLe64(canonical, entry.size);
    }
    Sha256 hash; hash.update(canonical.data(), canonical.size()); return "sha256:" + hash.finish();
}

std::string architecture() {
#if defined(_M_X64)
    return "x64";
#elif defined(_M_ARM64)
    return "arm64";
#else
    return "unknown";
#endif
}

std::string driveTypeName(UINT type) {
    switch (type) {
        case DRIVE_FIXED: return "FIXED";
        case DRIVE_REMOTE: return "REMOTE";
        case DRIVE_REMOVABLE: return "REMOVABLE";
        case DRIVE_CDROM: return "CDROM";
        case DRIVE_RAMDISK: return "RAMDISK";
        case DRIVE_NO_ROOT_DIR: return "NO_ROOT";
        default: return "UNKNOWN";
    }
}

std::string errorResponse(const std::string& requestId, const std::string& code, DWORD windowsError, const std::string& phase) {
    return "{\"schemaVersion\":1,\"helperVersion\":\"" + std::string(kHelperVersion) + "\",\"requestId\":" + escapeJson(requestId) +
        ",\"ok\":false,\"operation\":\"inspect\",\"error\":{\"code\":" + escapeJson(code) +
        ",\"windowsError\":" + std::to_string(windowsError) + ",\"phase\":" + escapeJson(phase) + ",\"retryable\":false}}";
}

struct InspectionError : std::runtime_error {
    std::string code;
    DWORD windowsError;
    std::string phase;
    InspectionError(std::string errorCode, DWORD nativeError, std::string errorPhase, const std::string& message)
        : std::runtime_error(message), code(std::move(errorCode)), windowsError(nativeError), phase(std::move(errorPhase)) {}
};

std::string inspect(const std::wstring& targetPath, const std::string& requestId) {
    const DWORD access = GENERIC_READ | READ_CONTROL;
    Handle file(CreateFileW(targetPath.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        throw InspectionError(error == ERROR_ACCESS_DENIED ? "ACCESS_DENIED" : "INSPECTION_FAILED", error, "open-target", "CreateFileW failed.");
    }

    FILE_BASIC_INFO basic{};
    FILE_STANDARD_INFO standard{};
    FILE_ID_INFO identity{};
    FILE_ATTRIBUTE_TAG_INFO tag{};
    FILE_COMPRESSION_INFO compression{};
    if (!GetFileInformationByHandleEx(file.value, FileBasicInfo, &basic, sizeof(basic)) ||
        !GetFileInformationByHandleEx(file.value, FileStandardInfo, &standard, sizeof(standard)) ||
        !GetFileInformationByHandleEx(file.value, FileIdInfo, &identity, sizeof(identity)) ||
        !GetFileInformationByHandleEx(file.value, FileAttributeTagInfo, &tag, sizeof(tag)) ||
        !GetFileInformationByHandleEx(file.value, FileCompressionInfo, &compression, sizeof(compression))) {
        throw InspectionError("INSPECTION_FAILED", GetLastError(), "file-information", "Handle metadata inspection failed.");
    }

    std::array<WCHAR, MAX_PATH + 1> volumeName{};
    std::array<WCHAR, 32> filesystemName{};
    DWORD volumeSerial = 0;
    DWORD maxComponent = 0;
    DWORD filesystemFlags = 0;
    if (!GetVolumeInformationByHandleW(file.value, volumeName.data(), static_cast<DWORD>(volumeName.size()), &volumeSerial,
        &maxComponent, &filesystemFlags, filesystemName.data(), static_cast<DWORD>(filesystemName.size()))) {
        throw InspectionError("UNSUPPORTED_FILESYSTEM", GetLastError(), "volume-information", "Volume inspection failed.");
    }
    const std::string filesystem = wideToUtf8(filesystemName.data());

    std::array<WCHAR, MAX_PATH + 1> volumePath{};
    UINT driveType = DRIVE_UNKNOWN;
    if (GetVolumePathNameW(targetPath.c_str(), volumePath.data(), static_cast<DWORD>(volumePath.size()))) driveType = GetDriveTypeW(volumePath.data());
    FILE_REMOTE_PROTOCOL_INFO remoteInfo{};
    const bool remoteProtocol = GetFileInformationByHandleEx(file.value, FileRemoteProtocolInfo, &remoteInfo, sizeof(remoteInfo)) != FALSE && remoteInfo.Protocol != 0;
    const bool remote = driveType == DRIVE_REMOTE || remoteProtocol;

    const bool reparse = (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    const bool normal = (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
    const SecurityInspection security = inspectSecurity(file.value);
    const auto listedStreams = normal ? enumerateFileStreams(file.value) : std::vector<std::pair<std::wstring, std::uint64_t>>{};
    StreamInspection backupStreams = normal ? inspectBackupStreams(file.value) : StreamInspection{};
    std::map<std::wstring, std::uint64_t> listed;
    for (const auto& entry : listedStreams) listed.emplace(entry.first, entry.second);
    std::map<std::wstring, std::uint64_t> backedUp;
    for (const auto& entry : backupStreams.entries) backedUp.emplace(entry.name, entry.size);
    if (listed != backedUp) throw InspectionError("ADS_INSPECTION_INCOMPLETE", ERROR_INVALID_DATA, "alternate-streams", "Stream enumeration methods disagreed.");

    const std::string adsDigest = streamDigest(backupStreams.entries);
    const std::string adsInventoryDigest = streamInventoryDigest(backupStreams.entries);
    const std::string attributes = fixedHex(static_cast<std::uint32_t>(basic.FileAttributes), 8);
    const std::string volumeSerialText = fixedHex(volumeSerial, 8);
    const std::string identityVolume = fixedHex(identity.VolumeSerialNumber, 16);
    const std::string fileId = hexBytes(identity.FileId.Identifier, sizeof(identity.FileId.Identifier));
    const bool readonly = (basic.FileAttributes & FILE_ATTRIBUTE_READONLY) != 0;
    const bool encrypted = (basic.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED) != 0;
    const bool compressed = (basic.FileAttributes & FILE_ATTRIBUTE_COMPRESSED) != 0;
    const bool sparse = (basic.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0 || backupStreams.sparsePresent;
    const bool noScrub = (basic.FileAttributes & FILE_ATTRIBUTE_NO_SCRUB_DATA) != 0;
    const bool integrity = (basic.FileAttributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) != 0;
    const bool offlineOrRecall = (basic.FileAttributes & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)) != 0;
    const bool persistentAcls = (filesystemFlags & FILE_PERSISTENT_ACLS) != 0;
    const bool localNtfsCandidate = filesystem == "NTFS" && persistentAcls && !remote && driveType == DRIVE_FIXED && normal && !reparse;

    std::string volumeCanonical = "filesystem=" + filesystem;
    volumeCanonical.push_back('\0');
    volumeCanonical += "serial=" + volumeSerialText;
    volumeCanonical.push_back('\0');
    volumeCanonical += "drive=" + driveTypeName(driveType);
    volumeCanonical.push_back('\0');
    volumeCanonical += "remote=" + std::string(remote ? "true" : "false");
    const std::string volumeFingerprint = digestTagged("wpb-volume-v1", volumeCanonical);
    std::string metadataCanonical = "schema=wpb-windows-metadata-v1";
    const auto addMetadataField = [&metadataCanonical](const std::string& name, const std::string& value) {
        metadataCanonical.push_back('\0');
        metadataCanonical += name + "=" + value;
    };
    addMetadataField("filesystem", filesystem);
    addMetadataField("remote", remote ? "true" : "false");
    addMetadataField("drive", driveTypeName(driveType));
    addMetadataField("volume", volumeSerialText);
    addMetadataField("identityVolume", identityVolume);
    addMetadataField("fileId", fileId);
    addMetadataField("links", std::to_string(standard.NumberOfLinks));
    addMetadataField("size", std::to_string(standard.EndOfFile.QuadPart));
    addMetadataField("attributes", attributes);
    addMetadataField("dacl", security.daclFingerprint);
    addMetadataField("owner", security.ownerFingerprint);
    addMetadataField("group", security.groupFingerprint);
    addMetadataField("ads", adsDigest);
    addMetadataField("compression", std::to_string(compression.CompressionFormat));
    const std::string metadataFingerprint = digestTagged("wpb-windows-metadata-v1", metadataCanonical);

    std::vector<std::string> reasons;
    if (filesystem != "NTFS") reasons.push_back("UNSUPPORTED_FILESYSTEM");
    if (remote) reasons.push_back("REMOTE_FILESYSTEM_UNSUPPORTED");
    if (driveType != DRIVE_FIXED) reasons.push_back("WINDOWS_DRIVE_TYPE_UNSUPPORTED");
    if (!persistentAcls) reasons.push_back("WINDOWS_PERSISTENT_ACL_UNAVAILABLE");
    if (!normal) reasons.push_back("NON_REGULAR_FILE");
    if (reparse) reasons.push_back("REPARSE_POINT_UNSUPPORTED");
    if (readonly) reasons.push_back("READ_ONLY_TARGET");
    if (standard.NumberOfLinks > 1) reasons.push_back("HARD_LINK_TARGET");
    if (security.daclProtected || security.explicitAceCount > 0) reasons.push_back("WINDOWS_SPECIAL_ACL");
    if (!backupStreams.entries.empty()) reasons.push_back("WINDOWS_ADS_UNSUPPORTED");
    if (backupStreams.eaPresent) reasons.push_back("WINDOWS_EA_UNSUPPORTED");
    if (sparse) reasons.push_back("WINDOWS_SPARSE_UNSUPPORTED");
    if (noScrub) reasons.push_back("WINDOWS_NO_SCRUB_UNSUPPORTED");
    if (integrity) reasons.push_back("WINDOWS_INTEGRITY_STREAM_UNSUPPORTED");
    if (offlineOrRecall) reasons.push_back("WINDOWS_OFFLINE_OR_RECALL_UNSUPPORTED");
    if (backupStreams.unknownPresent) reasons.push_back("WINDOWS_UNKNOWN_BACKUP_STREAM");
    if (encrypted) reasons.push_back("WINDOWS_ENCRYPTED_UNSUPPORTED");

    std::ostringstream blocking;
    blocking << '[';
    for (std::size_t index = 0; index < reasons.size(); ++index) {
        if (index) blocking << ',';
        blocking << "{\"code\":" << escapeJson(reasons[index]) << '}';
    }
    blocking << ']';

    std::ostringstream output;
    output << "{\"schemaVersion\":1,\"helperVersion\":\"" << kHelperVersion << "\",\"requestId\":" << escapeJson(requestId)
        << ",\"ok\":true,\"operation\":\"inspect\",\"adapter\":\"" << kAdapter << "\",\"architecture\":" << escapeJson(architecture())
        << ",\"filesystem\":{\"type\":" << escapeJson(filesystem) << ",\"remote\":" << (remote ? "true" : "false")
        << ",\"driveType\":" << escapeJson(driveTypeName(driveType)) << ",\"volumeSerial\":" << escapeJson(volumeSerialText)
        << ",\"volumeFingerprint\":" << escapeJson(volumeFingerprint) << "},\"file\":{\"normalFile\":" << (normal ? "true" : "false")
        << ",\"reparsePoint\":" << (reparse ? "true" : "false") << ",\"reparseTag\":" << (reparse ? escapeJson(fixedHex(tag.ReparseTag, 8)) : "null")
        << ",\"identity\":{\"volumeSerial\":" << escapeJson(identityVolume) << ",\"fileId\":" << escapeJson(fileId) << "},\"linkCount\":"
        << escapeJson(std::to_string(standard.NumberOfLinks)) << ",\"size\":" << escapeJson(std::to_string(standard.EndOfFile.QuadPart))
        << ",\"attributes\":" << escapeJson(attributes) << ",\"readonly\":" << (readonly ? "true" : "false") << "},\"security\":{\"daclFingerprint\":"
        << escapeJson(security.daclFingerprint) << ",\"daclProtected\":" << (security.daclProtected ? "true" : "false")
        << ",\"ownerFingerprint\":" << escapeJson(security.ownerFingerprint) << ",\"groupFingerprint\":" << escapeJson(security.groupFingerprint)
        << "},\"streams\":{\"count\":" << backupStreams.entries.size() << ",\"digest\":" << escapeJson(adsDigest)
        << ",\"inventoryDigest\":" << escapeJson(adsInventoryDigest)
        << "},\"compression\":{\"compressed\":" << (compressed ? "true" : "false") << ",\"format\":" << escapeJson(fixedHex(compression.CompressionFormat, 4))
        << "},\"encryption\":{\"encrypted\":" << (encrypted ? "true" : "false") << "},\"capabilities\":{\"completeForReplace\":false,\"localNtfsCandidate\":"
        << (localNtfsCandidate ? "true" : "false") << ",\"saclInspected\":false,\"extendedAttributesInspected\":true,\"securityResourceAttributesInspected\":false"
        << "},\"compatibility\":{\"explicitAccessRuleCount\":" << security.explicitAceCount << "},\"metadataFingerprint\":" << escapeJson(metadataFingerprint)
        << ",\"blockingReasons\":" << blocking.str() << '}';
    return output.str();
}

} // namespace

int main() {
    std::ios::sync_with_stdio(false);
    std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    std::string requestId;
    try {
        if (input.empty() || input.size() > kMaxInputBytes) throw InspectionError("INVALID_JSON", ERROR_INVALID_DATA, "protocol", "Request size is invalid.");
        const JsonValue request = JsonParser(input).parse();
        const JsonValue& schema = required(request, "schemaVersion", JsonValue::Type::Number);
        const JsonValue& operation = required(request, "operation", JsonValue::Type::String);
        const JsonValue& requestIdValue = required(request, "requestId", JsonValue::Type::String);
        requestId = requestIdValue.text;
        if (requestId.empty() || requestId.size() > 128) throw InspectionError("INVALID_REQUEST", ERROR_INVALID_DATA, "protocol", "requestId is invalid.");
        if (schema.text != "1") {
            std::cout << errorResponse(requestId, "HELPER_SCHEMA_UNSUPPORTED", ERROR_REVISION_MISMATCH, "protocol");
            return 2;
        }
        if (operation.text != "inspect") throw InspectionError("INVALID_REQUEST", ERROR_INVALID_FUNCTION, "protocol", "Only inspect is supported.");
        const JsonValue& target = required(request, "target", JsonValue::Type::Object);
        const std::string targetPathUtf8 = required(target, "path", JsonValue::Type::String).text;
        if (targetPathUtf8.empty()) throw InspectionError("INVALID_PATH", ERROR_INVALID_NAME, "protocol", "Target path is empty.");
        const std::wstring targetPath = utf8ToWide(targetPathUtf8);
        const bool driveAbsolute = targetPath.size() >= 3 && targetPath[1] == L':' && (targetPath[2] == L'\\' || targetPath[2] == L'/');
        const bool uncAbsolute = targetPath.size() >= 2 && targetPath[0] == L'\\' && targetPath[1] == L'\\';
        if (!driveAbsolute && !uncAbsolute) throw InspectionError("INVALID_PATH", ERROR_BAD_PATHNAME, "protocol", "Target path must be absolute.");
        std::cout << inspect(targetPath, requestId);
        return 0;
    } catch (const InspectionError& error) {
        std::cout << errorResponse(requestId, error.code, error.windowsError, error.phase);
        return 2;
    } catch (const std::exception&) {
        std::cout << errorResponse(requestId, "INSPECTION_FAILED", GetLastError(), "inspection");
        return 2;
    }
}
