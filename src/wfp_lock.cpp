// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// Project : https: // github.com/fmuecke/wfp-lock.git

#include "wfp_lock.h"

#include "endpoint.h"
#include "wfp_object_access.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <expected>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <windows.h>
#include <fwpmtypes.h>
#include <fwpmu.h> // requires include of fwmtypes and windows.h first
#include <objbase.h>
#include <sddl.h>
#include <winsock2.h>
#include <ws2tcpip.h>

namespace wfp_lock::detail
{

DWORD normalized_wfp_access_mask(DWORD mask)
{
    if ((mask & GENERIC_ALL) != 0)
    {
        mask = (mask & ~GENERIC_ALL) | FWPM_GENERIC_ALL;
    }
    if ((mask & GENERIC_READ) != 0)
    {
        mask = (mask & ~GENERIC_READ) | FWPM_GENERIC_READ;
    }
    return mask;
}

bool same_access_control_descriptor(PSECURITY_DESCRIPTOR actual, PSECURITY_DESCRIPTOR expected)
{
    if (!actual || !expected || !IsValidSecurityDescriptor(actual) ||
        !IsValidSecurityDescriptor(expected))
    {
        return false;
    }
    BOOL actual_present {};
    BOOL actual_defaulted {};
    PACL actual_dacl {};
    BOOL expected_present {};
    BOOL expected_defaulted {};
    PACL expected_dacl {};
    if (!GetSecurityDescriptorDacl(actual, &actual_present, &actual_dacl, &actual_defaulted) ||
        !GetSecurityDescriptorDacl(
            expected, &expected_present, &expected_dacl, &expected_defaulted) ||
        actual_present != expected_present || actual_defaulted != expected_defaulted ||
        !actual_dacl || !expected_dacl)
    {
        return false;
    }
    return actual_dacl->AclSize == expected_dacl->AclSize &&
           std::memcmp(actual_dacl, expected_dacl, actual_dacl->AclSize) == 0;
}

bool same_wfp_object_access_control_descriptor(
    PSECURITY_DESCRIPTOR actual, PSECURITY_DESCRIPTOR expected)
{
    if (!actual || !expected || !IsValidSecurityDescriptor(actual) ||
        !IsValidSecurityDescriptor(expected))
    {
        return false;
    }
    BOOL actual_present {};
    BOOL actual_defaulted {};
    PACL actual_dacl {};
    BOOL expected_present {};
    BOOL expected_defaulted {};
    PACL expected_dacl {};
    if (!GetSecurityDescriptorDacl(actual, &actual_present, &actual_dacl, &actual_defaulted) ||
        !GetSecurityDescriptorDacl(
            expected, &expected_present, &expected_dacl, &expected_defaulted) ||
        !actual_present || !expected_present || !actual_dacl || !expected_dacl)
    {
        return false;
    }

    std::vector<const ACCESS_ALLOWED_ACE*> expected_aces;
    for (DWORD index = 0; index < expected_dacl->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(expected_dacl, index, &entry))
        {
            return false;
        }
        const auto* header = static_cast<const ACE_HEADER*>(entry);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || (header->AceFlags & INHERITED_ACE) != 0)
        {
            return false;
        }
        expected_aces.push_back(static_cast<const ACCESS_ALLOWED_ACE*>(entry));
    }

    std::vector<const ACCESS_ALLOWED_ACE*> actual_aces;
    for (DWORD index = 0; index < actual_dacl->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(actual_dacl, index, &entry))
        {
            return false;
        }
        const auto* header = static_cast<const ACE_HEADER*>(entry);
        if ((header->AceFlags & INHERITED_ACE) != 0)
        {
            continue;
        }
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE)
        {
            return false;
        }
        actual_aces.push_back(static_cast<const ACCESS_ALLOWED_ACE*>(entry));
    }
    if (actual_aces.size() != expected_aces.size())
    {
        return false;
    }

    std::vector<bool> matched(actual_aces.size());
    for (const ACCESS_ALLOWED_ACE* expected_ace : expected_aces)
    {
        const PSID expected_sid =
            const_cast<PSID>(static_cast<const void*>(&expected_ace->SidStart));
        const DWORD expected_mask = normalized_wfp_access_mask(expected_ace->Mask);
        bool found {};
        for (std::size_t index = 0; index < actual_aces.size(); ++index)
        {
            const ACCESS_ALLOWED_ACE* actual_ace = actual_aces[index];
            const PSID actual_sid =
                const_cast<PSID>(static_cast<const void*>(&actual_ace->SidStart));
            if (!matched[index] && normalized_wfp_access_mask(actual_ace->Mask) == expected_mask &&
                EqualSid(actual_sid, expected_sid))
            {
                matched[index] = true;
                found = true;
                break;
            }
        }
        if (!found)
        {
            return false;
        }
    }
    return true;
}

bool has_protected_dacl(PSECURITY_DESCRIPTOR descriptor)
{
    if (!descriptor || !IsValidSecurityDescriptor(descriptor))
    {
        return false;
    }
    SECURITY_DESCRIPTOR_CONTROL control {};
    DWORD revision {};
    return GetSecurityDescriptorControl(descriptor, &control, &revision) &&
           (control & SE_DACL_PROTECTED) != 0;
}

namespace
{

std::optional<std::uint16_t> parse_tcp_port(std::wstring_view text)
{
    if (text.empty() || text.size() > 5)
    {
        return std::nullopt;
    }
    std::uint32_t value {};
    for (const wchar_t character : text)
    {
        if (character < L'0' || character > L'9')
        {
            return std::nullopt;
        }
        value = value * 10 + static_cast<std::uint32_t>(character - L'0');
    }
    if (value == 0 || value > 65535)
    {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(value);
}

} // namespace

std::optional<Endpoint> parse_endpoint(std::wstring_view text)
{
    const auto separator = text.rfind(L':');
    if (separator == std::wstring_view::npos || text.find(L'\0') != std::wstring_view::npos)
    {
        return std::nullopt;
    }
    const auto port = parse_tcp_port(text.substr(separator + 1));
    if (!port)
    {
        return std::nullopt;
    }
    const auto host = text.substr(0, separator);
    Endpoint endpoint;
    endpoint.port = *port;
    if (host.size() >= 2 && host.front() == L'[' && host.back() == L']')
    {
        const std::wstring address(host.substr(1, host.size() - 2));
        std::array<std::uint8_t, 16> bytes {};
        if (InetPtonW(AF_INET6, address.c_str(), bytes.data()) != 1)
        {
            return std::nullopt;
        }
        constexpr std::array<std::uint8_t, 12> mapped_prefix {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
        };
        const bool unspecified = bytes == std::array<std::uint8_t, 16> {};
        const bool multicast = bytes[0] == 0xff;
        const bool mapped = std::equal(mapped_prefix.begin(), mapped_prefix.end(), bytes.begin());
        if (unspecified || multicast || mapped)
        {
            return std::nullopt;
        }
        endpoint.address_v6 = bytes;
        return endpoint;
    }
    const std::wstring address(host);
    IN_ADDR value {};
    if (InetPtonW(AF_INET, address.c_str(), &value) != 1)
    {
        return std::nullopt;
    }
    const std::uint32_t host_order = ntohl(value.s_addr);
    const bool multicast = (host_order >> 28) == 0xE;
    if (host_order == 0 || host_order == 0xFFFFFFFF || multicast)
    {
        return std::nullopt;
    }
    endpoint.address_v4 = host_order;
    return endpoint;
}

} // namespace wfp_lock::detail

namespace wfp_lock
{
namespace
{

constexpr GUID provider_key {
    0x9b2365a6, 0xf9b9, 0x49f9, {0xab, 0xdb, 0x19, 0x65, 0x79, 0xb1, 0x48, 0x1c}
};
constexpr GUID sublayer_key {
    0x42f667f1, 0x2945, 0x48bd, {0x81, 0x44, 0x0b, 0xd0, 0x21, 0xe6, 0x74, 0x31}
};
constexpr std::uint64_t permit_weight = 0xF000000000000000ULL;
constexpr std::uint64_t block_weight = 0x1000000000000000ULL;
constexpr std::uint16_t sublayer_weight = 0x8000;
constexpr std::size_t max_allow_entries = 32;
// Filters written by wfp-lock 0.9 and earlier append the loopback port to the policy identity.
// They are still recognized so that apply and remove replace them.
constexpr std::size_t legacy_port_suffix = sizeof(std::uint16_t);
// The tag predates arbitrary endpoints; it is kept to identify existing policies.
constexpr std::array<UINT8, 16> policy_tag {
    'w', 'f', 'p', '-', 'l', 'o', 'o', 'p', 'b', 'a', 'c', 'k', '-', 'v', '1', 0
};

using LocalMemory = std::unique_ptr<void, decltype(&LocalFree)>;

struct Error
{
    ExitCode exit_code;
    std::uint32_t native_code;
    std::wstring message;
};

template <typename T> using Result = std::expected<T, Error>;

struct Engine
{
    HANDLE value {};

    ~Engine()
    {
        if (value)
        {
            FwpmEngineClose0(value);
        }
    }

    Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Engine& operator=(Engine&& other) noexcept
    {
        if (this != &other)
        {
            if (value)
            {
                FwpmEngineClose0(value);
            }
            value = std::exchange(other.value, nullptr);
        }
        return *this;
    }
};

class SharedInfrastructureMutex
{
  public:
    explicit SharedInfrastructureMutex(HANDLE value) : value_(value) {}

    ~SharedInfrastructureMutex()
    {
        if (value_)
        {
            ReleaseMutex(value_);
            CloseHandle(value_);
        }
    }

    SharedInfrastructureMutex(const SharedInfrastructureMutex&) = delete;
    SharedInfrastructureMutex& operator=(const SharedInfrastructureMutex&) = delete;
    SharedInfrastructureMutex(SharedInfrastructureMutex&& other) noexcept
        : value_(std::exchange(other.value_, nullptr))
    {
    }
    SharedInfrastructureMutex& operator=(SharedInfrastructureMutex&& other) noexcept
    {
        if (this != &other)
        {
            if (value_)
            {
                ReleaseMutex(value_);
                CloseHandle(value_);
            }
            value_ = std::exchange(other.value_, nullptr);
        }
        return *this;
    }

  private:
    HANDLE value_ {};
};

struct Rule
{
    const GUID* layer;
    FWP_ACTION_TYPE action;
    std::uint64_t weight;
    std::uint8_t protocol;
    std::optional<std::uint32_t> address_v4;
    std::optional<std::array<UINT8, 16>> address_v6;
    std::optional<std::uint16_t> port;
};

struct PolicyInput
{
    std::wstring user;
    std::vector<detail::Endpoint> allowed;
};

Error error(ExitCode exit_code, std::uint32_t native_code, std::wstring message)
{
    return Error {exit_code, native_code, std::move(message)};
}

std::wstring system_message(DWORD code)
{
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        0,
        reinterpret_cast<wchar_t*>(&buffer),
        0,
        nullptr);
    LocalMemory memory(buffer, LocalFree);
    if (!length)
    {
        return L"error " + std::to_wstring(code);
    }
    std::wstring text(buffer, length);
    while (!text.empty() && std::iswspace(text.back()))
    {
        text.pop_back();
    }
    return text;
}

Error win32_error(ExitCode exit_code, DWORD code, std::wstring_view operation)
{
    return error(exit_code,
        code,
        std::wstring(operation) + L": " + system_message(code) + L" (" + std::to_wstring(code) +
            L")");
}

Result<SharedInfrastructureMutex> lock_shared_infrastructure()
{
    // The mutex is global so elevated applies from different interactive sessions
    // cannot snapshot and replace the provider/sublayer DACL concurrently.
    constexpr wchar_t mutex_name[] = L"Global\\wfp-lock-shared-infrastructure-v1";
    constexpr wchar_t mutex_dacl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    PSECURITY_DESCRIPTOR descriptor {};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            mutex_dacl, SDDL_REVISION_1, &descriptor, nullptr))
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, GetLastError(), L"Build shared-infrastructure mutex DACL"));
    }
    LocalMemory memory(descriptor, LocalFree);
    SECURITY_ATTRIBUTES attributes {sizeof(attributes), descriptor, FALSE};
    HANDLE mutex = CreateMutexW(&attributes, FALSE, mutex_name);
    if (!mutex)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, GetLastError(), L"Create shared-infrastructure mutex"));
    }
    const DWORD wait = WaitForSingleObject(mutex, INFINITE);
    if (wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED)
    {
        return SharedInfrastructureMutex(mutex);
    }
    const DWORD code = wait == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
    CloseHandle(mutex);
    return std::unexpected(
        win32_error(ExitCode::wfp, code, L"Wait for shared-infrastructure mutex"));
}

Result<bool> is_elevated()
{
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators {};
    if (!AllocateAndInitializeSid(&authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0,
            0,
            0,
            0,
            0,
            0,
            &administrators))
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, GetLastError(), L"Create Administrators SID"));
    }
    BOOL member {};
    const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
    const DWORD code = checked ? ERROR_SUCCESS : GetLastError();
    FreeSid(administrators);
    if (!checked)
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, code, L"Check administrator membership"));
    }
    return member != FALSE;
}

Result<void> require_elevation()
{
    auto elevated = is_elevated();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    if (!*elevated)
    {
        return std::unexpected(error(ExitCode::precondition,
            ERROR_ACCESS_DENIED,
            L"wfp-lock must run from an elevated Administrator session"));
    }
    return {};
}

Result<std::vector<std::byte>> resolve_account_sid(std::wstring_view account)
{
    std::wstring name(account);
    DWORD sid_size {};
    DWORD domain_size {};
    SID_NAME_USE use {};
    LookupAccountNameW(nullptr, name.c_str(), nullptr, &sid_size, nullptr, &domain_size, &use);
    const DWORD first_error = GetLastError();
    if (first_error != ERROR_INSUFFICIENT_BUFFER || sid_size == 0)
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, first_error, L"Resolve local account"));
    }
    std::vector<std::byte> sid(sid_size);
    std::wstring domain(domain_size, L'\0');
    if (!LookupAccountNameW(
            nullptr, name.c_str(), sid.data(), &sid_size, domain.data(), &domain_size, &use))
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, GetLastError(), L"Resolve local account"));
    }
    sid.resize(sid_size);
    return sid;
}

Result<std::vector<std::byte>> current_user_sid()
{
    HANDLE token {};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, GetLastError(), L"Open caller token"));
    }
    const auto close = [&] { CloseHandle(token); };
    DWORD size {};
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    const DWORD first_error = GetLastError();
    if (first_error != ERROR_INSUFFICIENT_BUFFER || size == 0)
    {
        close();
        return std::unexpected(
            win32_error(ExitCode::precondition, first_error, L"Read caller token user"));
    }
    std::vector<std::byte> user(size);
    if (!GetTokenInformation(token, TokenUser, user.data(), size, &size))
    {
        const DWORD code = GetLastError();
        close();
        return std::unexpected(
            win32_error(ExitCode::precondition, code, L"Read caller token user"));
    }
    close();
    const auto* token_user = reinterpret_cast<const TOKEN_USER*>(user.data());
    if (!token_user->User.Sid || !IsValidSid(token_user->User.Sid))
    {
        return std::unexpected(error(ExitCode::precondition,
            ERROR_INVALID_DATA,
            L"Caller token contains an invalid user SID"));
    }
    const DWORD sid_size = GetLengthSid(token_user->User.Sid);
    std::vector<std::byte> sid(sid_size);
    std::memcpy(sid.data(), token_user->User.Sid, sid_size);
    return sid;
}

Result<void> require_self_or_elevation(PSID target_sid)
{
    auto elevated = is_elevated();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    if (*elevated)
    {
        return {};
    }
    auto caller_sid = current_user_sid();
    if (!caller_sid)
    {
        return std::unexpected(caller_sid.error());
    }
    if (!EqualSid(caller_sid->data(), target_sid))
    {
        return std::unexpected(error(ExitCode::precondition,
            ERROR_ACCESS_DENIED,
            L"A non-administrator may inspect only its own wfp-lock policy"));
    }
    return {};
}

Result<std::wstring> sid_string(PSID sid)
{
    LPWSTR text {};
    if (!ConvertSidToStringSidW(sid, &text))
    {
        return std::unexpected(
            win32_error(ExitCode::precondition, GetLastError(), L"Convert SID to text"));
    }
    LocalMemory memory(text, LocalFree);
    return std::wstring(text);
}

Result<std::vector<std::byte>> user_condition_descriptor(PSID sid)
{
    auto text = sid_string(sid);
    if (!text)
    {
        return std::unexpected(text.error());
    }
    PSECURITY_DESCRIPTOR descriptor {};
    // This descriptor is the FWPM_CONDITION_ALE_USER_ID match value, not the
    // WFP object's management ACL. It binds each filter to the selected account
    // SID so another user's traffic cannot satisfy the rule.
    const std::wstring sddl = L"D:(A;;CC;;;" + *text + L")";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, GetLastError(), L"Build target-user condition"));
    }
    LocalMemory memory(descriptor, LocalFree);
    const DWORD size = GetSecurityDescriptorLength(descriptor);
    std::vector<std::byte> result(size);
    std::memcpy(result.data(), descriptor, size);
    return result;
}

Result<std::vector<std::byte>> wfp_object_descriptor(std::span<PSID const> read_users)
{
    std::wstring sddl(detail::administrative_wfp_object_dacl_sddl);
    for (PSID user : read_users)
    {
        auto text = sid_string(user);
        if (!text)
        {
            return std::unexpected(text.error());
        }
        sddl += L"(A;;GR;;;" + *text + L")";
    }
    PSECURITY_DESCRIPTOR descriptor {};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, GetLastError(), L"Build WFP object access control"));
    }
    LocalMemory memory(descriptor, LocalFree);
    const DWORD size = GetSecurityDescriptorLength(descriptor);
    std::vector<std::byte> result(size);
    std::memcpy(result.data(), descriptor, size);
    return result;
}

Result<PACL> wfp_object_dacl(const std::vector<std::byte>& descriptor)
{
    if (descriptor.empty())
    {
        return std::unexpected(
            error(ExitCode::wfp, ERROR_INVALID_DATA, L"WFP object access control is empty"));
    }
    BOOL present {};
    BOOL defaulted {};
    PACL dacl {};
    const auto security_descriptor =
        reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(descriptor.data()));
    if (!GetSecurityDescriptorDacl(security_descriptor, &present, &dacl, &defaulted) || !present ||
        !dacl)
    {
        return std::unexpected(
            error(ExitCode::wfp, ERROR_INVALID_DATA, L"WFP object access control has no DACL"));
    }
    return dacl;
}

Result<Engine> open_engine(ExitCode exit_code = ExitCode::wfp)
{
    Engine engine;
    const DWORD code = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine.value);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(exit_code, code, L"Open WFP engine"));
    }
    return engine;
}

std::vector<UINT8> policy_identity(PSID sid)
{
    const auto size = GetLengthSid(sid);
    std::vector<UINT8> identity(policy_tag.begin(), policy_tag.end());
    const auto* sid_bytes = static_cast<const UINT8*>(sid);
    identity.insert(identity.end(), sid_bytes, sid_bytes + size);
    return identity;
}

bool same_blob(const FWP_BYTE_BLOB& blob, const std::vector<UINT8>& expected)
{
    return blob.size == expected.size() && blob.data &&
           std::memcmp(blob.data, expected.data(), expected.size()) == 0;
}

bool is_owned_for(const FWPM_FILTER0& filter, const std::vector<UINT8>& identity)
{
    return filter.providerKey && IsEqualGUID(*filter.providerKey, provider_key) &&
           IsEqualGUID(filter.subLayerKey, sublayer_key) && filter.providerData.data &&
           (filter.providerData.size == identity.size() ||
               filter.providerData.size == identity.size() + legacy_port_suffix) &&
           std::memcmp(filter.providerData.data, identity.data(), identity.size()) == 0;
}

const FWPM_FILTER_CONDITION0* find_condition(const FWPM_FILTER0& filter, const GUID& field)
{
    for (UINT32 index = 0; index < filter.numFilterConditions; ++index)
    {
        if (IsEqualGUID(filter.filterCondition[index].fieldKey, field))
        {
            return &filter.filterCondition[index];
        }
    }
    return nullptr;
}

bool same_user_descriptor(const FWP_BYTE_BLOB* actual, const std::vector<std::byte>& expected)
{
    return actual && actual->data &&
           detail::same_access_control_descriptor(
               reinterpret_cast<PSECURITY_DESCRIPTOR>(actual->data),
               reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(expected.data())));
}

std::wstring descriptor_dacl_sddl(PSECURITY_DESCRIPTOR descriptor)
{
    LPWSTR text {};
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text, nullptr))
    {
        return L"<unavailable>";
    }
    LocalMemory memory(text, LocalFree);
    return text;
}

bool has_safe_shared_object_access(PSECURITY_DESCRIPTOR descriptor, PSID required_reader)
{
    if (!detail::has_protected_dacl(descriptor))
    {
        return false;
    }
    BOOL present {};
    BOOL defaulted {};
    PACL dacl {};
    if (!GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) || !present || !dacl)
    {
        return false;
    }
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID system {};
    PSID administrators {};
    const BOOL system_created = AllocateAndInitializeSid(
        &authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system);
    const BOOL administrators_created = AllocateAndInitializeSid(&authority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0,
        0,
        0,
        0,
        0,
        0,
        &administrators);
    if (!system_created || !administrators_created)
    {
        if (system_created)
        {
            FreeSid(system);
        }
        if (administrators_created)
        {
            FreeSid(administrators);
        }
        return false;
    }
    bool system_found {};
    bool administrators_found {};
    bool reader_found {};
    bool valid = true;
    for (DWORD index = 0; valid && index < dacl->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(dacl, index, &entry))
        {
            valid = false;
            break;
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(entry);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0)
        {
            valid = false;
            break;
        }
        const PSID sid = const_cast<PSID>(static_cast<const void*>(&ace->SidStart));
        const DWORD mask = detail::normalized_wfp_access_mask(ace->Mask);
        if (EqualSid(sid, system))
        {
            valid = !system_found && mask == FWPM_GENERIC_ALL;
            system_found = true;
        }
        else if (EqualSid(sid, administrators))
        {
            valid = !administrators_found && mask == FWPM_GENERIC_ALL;
            administrators_found = true;
        }
        else
        {
            valid = mask == FWPM_GENERIC_READ;
            if (EqualSid(sid, required_reader))
            {
                valid = valid && !reader_found;
                reader_found = true;
            }
        }
    }
    FreeSid(system);
    FreeSid(administrators);
    return valid && system_found && administrators_found && reader_found;
}

Result<void> verify_provider_access(HANDLE engine, PSID required_reader)
{
    PSECURITY_DESCRIPTOR actual {};
    const DWORD code = FwpmProviderGetSecurityInfoByKey0(engine,
        &provider_key,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &actual);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, code, L"Read wfp-lock provider access control"));
    }
    const bool matches = has_safe_shared_object_access(actual, required_reader);
    const std::wstring actual_sddl = matches ? L"" : descriptor_dacl_sddl(actual);
    FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    if (!matches)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-lock provider access control does not match: " + actual_sddl));
    }
    return {};
}

Result<void> verify_sublayer_access(HANDLE engine, PSID required_reader)
{
    PSECURITY_DESCRIPTOR actual {};
    const DWORD code = FwpmSubLayerGetSecurityInfoByKey0(engine,
        &sublayer_key,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &actual);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, code, L"Read wfp-lock sublayer access control"));
    }
    const bool matches = has_safe_shared_object_access(actual, required_reader);
    FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    if (!matches)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-lock sublayer access control does not match"));
    }
    return {};
}

Result<void> verify_filter_access(
    HANDLE engine, const GUID& key, const std::vector<std::byte>& expected)
{
    PSECURITY_DESCRIPTOR actual {};
    const DWORD code = FwpmFilterGetSecurityInfoByKey0(
        engine, &key, DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &actual);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, code, L"Read wfp-lock filter access control"));
    }
    const bool matches = detail::same_wfp_object_access_control_descriptor(
        actual, reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(expected.data())));
    FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    if (!matches)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-lock filter access control does not match"));
    }
    return {};
}

bool has_expected_provider_properties(const FWPM_PROVIDER0& provider)
{
    return provider.flags == FWPM_PROVIDER_FLAG_PERSISTENT;
}

bool has_expected_sublayer_properties(const FWPM_SUBLAYER0& sublayer)
{
    return sublayer.flags == FWPM_SUBLAYER_FLAG_PERSISTENT && sublayer.providerKey &&
           IsEqualGUID(*sublayer.providerKey, provider_key) && sublayer.weight >= sublayer_weight;
}

Error unexpected_sublayer_properties(ExitCode exit_code, const FWPM_SUBLAYER0& sublayer)
{
    const bool persistent = sublayer.flags == FWPM_SUBLAYER_FLAG_PERSISTENT;
    const bool expected_provider =
        sublayer.providerKey && IsEqualGUID(*sublayer.providerKey, provider_key);
    const bool minimum_weight = sublayer.weight >= sublayer_weight;
    return error(exit_code,
        ERROR_INVALID_DATA,
        L"wfp-lock sublayer does not match the policy (persistent=" + std::to_wstring(persistent) +
            L", expected-provider=" + std::to_wstring(expected_provider) + L", minimum-weight=" +
            std::to_wstring(minimum_weight) + L", weight=" + std::to_wstring(sublayer.weight) +
            L")");
}

bool matches_user(const FWPM_FILTER0& filter, const std::vector<std::byte>& user_sd)
{
    const auto* user = find_condition(filter, FWPM_CONDITION_ALE_USER_ID);
    return user && user->matchType == FWP_MATCH_EQUAL &&
           user->conditionValue.type == FWP_SECURITY_DESCRIPTOR_TYPE &&
           same_user_descriptor(user->conditionValue.sd, user_sd);
}

Result<void> enumerate_filters(
    HANDLE engine, const std::function<Result<void>(const FWPM_FILTER0&)>& visitor)
{
    HANDLE enumeration {};
    DWORD code = FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration);
    if (code == FWP_E_NEVER_MATCH)
    {
        return {};
    }
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Create WFP filter enumeration"));
    }
    const auto close = [&] { FwpmFilterDestroyEnumHandle0(engine, enumeration); };
    for (;;)
    {
        FWPM_FILTER0** filters {};
        UINT32 count {};
        code = FwpmFilterEnum0(engine, enumeration, 64, &filters, &count);
        if (code != ERROR_SUCCESS)
        {
            close();
            return std::unexpected(win32_error(ExitCode::wfp, code, L"Enumerate WFP filters"));
        }
        for (UINT32 index = 0; index < count; ++index)
        {
            auto result = visitor(*filters[index]);
            if (!result)
            {
                FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
                close();
                return std::unexpected(result.error());
            }
        }
        FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        if (count == 0)
        {
            break;
        }
    }
    close();
    return {};
}

Result<std::vector<std::vector<std::byte>>> managed_policy_user_sids(HANDLE engine)
{
    std::vector<std::vector<std::byte>> users;
    auto enumerated = enumerate_filters(engine,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (!filter.providerKey || !IsEqualGUID(*filter.providerKey, provider_key) ||
                !IsEqualGUID(filter.subLayerKey, sublayer_key) || !filter.providerData.data ||
                filter.providerData.size < policy_tag.size() ||
                std::memcmp(filter.providerData.data, policy_tag.data(), policy_tag.size()) != 0)
            {
                return {};
            }
            const auto* sid = filter.providerData.data + policy_tag.size();
            const PSID policy_sid = const_cast<void*>(static_cast<const void*>(sid));
            const std::size_t sid_capacity = filter.providerData.size - policy_tag.size();
            if (sid_capacity < SECURITY_SID_SIZE(0) ||
                sid_capacity <
                    SECURITY_SID_SIZE(static_cast<const SID*>(policy_sid)->SubAuthorityCount) ||
                !IsValidSid(policy_sid))
            {
                return std::unexpected(error(ExitCode::wfp,
                    ERROR_INVALID_DATA,
                    L"wfp-lock filter contains an invalid managed-account SID"));
            }
            const DWORD sid_size = GetLengthSid(policy_sid);
            if (filter.providerData.size != policy_tag.size() + sid_size &&
                filter.providerData.size != policy_tag.size() + sid_size + legacy_port_suffix)
            {
                return std::unexpected(error(ExitCode::wfp,
                    ERROR_INVALID_DATA,
                    L"wfp-lock filter contains malformed policy identity data"));
            }
            const auto already_present = std::any_of(users.begin(),
                users.end(),
                [&](const std::vector<std::byte>& existing)
                {
                    return existing.size() == sid_size &&
                           EqualSid(const_cast<void*>(static_cast<const void*>(existing.data())),
                               policy_sid);
                });
            if (!already_present)
            {
                std::vector<std::byte> copy(sid_size);
                std::memcpy(copy.data(), sid, sid_size);
                users.push_back(std::move(copy));
            }
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    return users;
}

Result<std::vector<std::byte>> infrastructure_descriptor(
    HANDLE engine, PSID additional_user = nullptr)
{
    auto users = managed_policy_user_sids(engine);
    if (!users)
    {
        return std::unexpected(users.error());
    }
    const auto present =
        additional_user &&
        std::any_of(users->begin(),
            users->end(),
            [&](const std::vector<std::byte>& existing)
            {
                return EqualSid(
                    const_cast<void*>(static_cast<const void*>(existing.data())), additional_user);
            });
    if (additional_user && !present)
    {
        const DWORD size = GetLengthSid(additional_user);
        std::vector<std::byte> copy(size);
        std::memcpy(copy.data(), additional_user, size);
        users->push_back(std::move(copy));
    }
    std::vector<PSID> identities;
    identities.reserve(users->size());
    for (const auto& user : *users)
    {
        identities.push_back(const_cast<void*>(static_cast<const void*>(user.data())));
    }
    return wfp_object_descriptor(identities);
}

bool has_explicit_access_ace(PACL dacl, PSID sid, DWORD mask)
{
    for (DWORD index = 0; index < dacl->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(dacl, index, &entry))
        {
            return false;
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(entry);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != 0)
        {
            continue;
        }
        const PSID ace_sid = const_cast<PSID>(static_cast<const void*>(&ace->SidStart));
        if (ace->Mask == mask && EqualSid(ace_sid, sid))
        {
            return true;
        }
    }
    return false;
}

Result<void> grant_filter_enumeration(HANDLE engine, PSID user)
{
    PSECURITY_DESCRIPTOR descriptor {};
    const DWORD read = FwpmFilterGetSecurityInfoByKey0(engine,
        nullptr,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &descriptor);
    if (read != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, read, L"Read WFP filter-container access control"));
    }
    BOOL present {};
    BOOL defaulted {};
    PACL existing {};
    if (!GetSecurityDescriptorDacl(descriptor, &present, &existing, &defaulted) || !present ||
        !existing)
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
        return std::unexpected(
            error(ExitCode::wfp, ERROR_INVALID_DATA, L"WFP filter container has no DACL"));
    }
    if (has_explicit_access_ace(existing, user, FWPM_ACTRL_ENUM))
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
        return {};
    }
    const DWORD addition = sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(user);
    std::vector<std::byte> storage(existing->AclSize + addition);
    auto* replacement = reinterpret_cast<PACL>(storage.data());
    if (!InitializeAcl(replacement, static_cast<DWORD>(storage.size()), existing->AclRevision))
    {
        const DWORD code = GetLastError();
        FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
        return std::unexpected(
            win32_error(ExitCode::wfp, code, L"Create WFP filter-container DACL"));
    }
    for (DWORD index = 0; index < existing->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(existing, index, &entry) || !AddAce(replacement,
                                                    replacement->AclRevision,
                                                    MAXDWORD,
                                                    entry,
                                                    static_cast<PACE_HEADER>(entry)->AceSize))
        {
            const DWORD code = GetLastError();
            FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
            return std::unexpected(
                win32_error(ExitCode::wfp, code, L"Copy WFP filter-container access control"));
        }
    }
    if (!AddAccessAllowedAceEx(replacement, replacement->AclRevision, 0, FWPM_ACTRL_ENUM, user))
    {
        const DWORD code = GetLastError();
        FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Grant WFP filter enumeration"));
    }
    const DWORD write = FwpmFilterSetSecurityInfoByKey0(
        engine, nullptr, DACL_SECURITY_INFORMATION, nullptr, nullptr, replacement, nullptr);
    FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
    if (write != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, write, L"Grant WFP filter enumeration"));
    }
    return {};
}

Result<void> remove_filter_enumeration(HANDLE engine, PSID user)
{
    PSECURITY_DESCRIPTOR descriptor {};
    const DWORD read = FwpmFilterGetSecurityInfoByKey0(engine,
        nullptr,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &descriptor);
    if (read != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, read, L"Read WFP filter-container access control"));
    }
    BOOL present {};
    BOOL defaulted {};
    PACL existing {};
    if (!GetSecurityDescriptorDacl(descriptor, &present, &existing, &defaulted) || !present ||
        !existing)
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
        return std::unexpected(
            error(ExitCode::wfp, ERROR_INVALID_DATA, L"WFP filter container has no DACL"));
    }
    if (!has_explicit_access_ace(existing, user, FWPM_ACTRL_ENUM))
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
        return {};
    }
    std::vector<std::byte> storage(existing->AclSize);
    auto* replacement = reinterpret_cast<PACL>(storage.data());
    if (!InitializeAcl(replacement, static_cast<DWORD>(storage.size()), existing->AclRevision))
    {
        const DWORD code = GetLastError();
        FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
        return std::unexpected(
            win32_error(ExitCode::wfp, code, L"Create WFP filter-container DACL"));
    }
    for (DWORD index = 0; index < existing->AceCount; ++index)
    {
        void* entry {};
        if (!GetAce(existing, index, &entry))
        {
            const DWORD code = GetLastError();
            FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
            return std::unexpected(
                win32_error(ExitCode::wfp, code, L"Read WFP filter-container access control"));
        }
        const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(entry);
        const PSID ace_sid = const_cast<PSID>(static_cast<const void*>(&ace->SidStart));
        if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Header.AceFlags == 0 &&
            ace->Mask == FWPM_ACTRL_ENUM && EqualSid(ace_sid, user))
        {
            continue;
        }
        if (!AddAce(replacement,
                replacement->AclRevision,
                MAXDWORD,
                entry,
                static_cast<PACE_HEADER>(entry)->AceSize))
        {
            const DWORD code = GetLastError();
            FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
            return std::unexpected(
                win32_error(ExitCode::wfp, code, L"Copy WFP filter-container access control"));
        }
    }
    const DWORD write = FwpmFilterSetSecurityInfoByKey0(
        engine, nullptr, DACL_SECURITY_INFORMATION, nullptr, nullptr, replacement, nullptr);
    FwpmFreeMemory0(reinterpret_cast<void**>(&descriptor));
    if (write != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, write, L"Remove WFP filter enumeration"));
    }
    return {};
}

Result<void> ensure_infrastructure(HANDLE engine, const std::vector<std::byte>& object_descriptor)
{
    auto dacl = wfp_object_dacl(object_descriptor);
    if (!dacl)
    {
        return std::unexpected(dacl.error());
    }
    FWPM_PROVIDER0* provider {};
    DWORD code = FwpmProviderGetByKey0(engine, &provider_key, &provider);
    if (code == ERROR_SUCCESS)
    {
        const bool properties_match = has_expected_provider_properties(*provider);
        FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
        if (!properties_match)
        {
            return std::unexpected(error(ExitCode::wfp,
                ERROR_INVALID_DATA,
                L"Existing wfp-lock provider does not match the policy"));
        }
        code = FwpmProviderSetSecurityInfoByKey0(
            engine, &provider_key, DACL_SECURITY_INFORMATION, nullptr, nullptr, *dacl, nullptr);
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(
                win32_error(ExitCode::wfp, code, L"Restore wfp-lock provider access control"));
        }
    }
    else if (code == FWP_E_PROVIDER_NOT_FOUND)
    {
        FWPM_PROVIDER0 new_provider {};
        new_provider.providerKey = provider_key;
        new_provider.displayData.name = const_cast<wchar_t*>(L"wfp-lock Provider");
        new_provider.displayData.description =
            const_cast<wchar_t*>(L"Persistent per-user outbound TCP allow lists");
        new_provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        code = FwpmProviderAdd0(engine,
            &new_provider,
            reinterpret_cast<PSECURITY_DESCRIPTOR>(
                const_cast<std::byte*>(object_descriptor.data())));
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(win32_error(ExitCode::wfp, code, L"Add wfp-lock provider"));
        }
    }
    else
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Read wfp-lock provider"));
    }

    FWPM_SUBLAYER0* sublayer {};
    code = FwpmSubLayerGetByKey0(engine, &sublayer_key, &sublayer);
    if (code == ERROR_SUCCESS)
    {
        const bool properties_match = has_expected_sublayer_properties(*sublayer);
        if (!properties_match)
        {
            const Error mismatch = unexpected_sublayer_properties(ExitCode::wfp, *sublayer);
            FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
            return std::unexpected(mismatch);
        }
        FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
        code = FwpmSubLayerSetSecurityInfoByKey0(
            engine, &sublayer_key, DACL_SECURITY_INFORMATION, nullptr, nullptr, *dacl, nullptr);
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(
                win32_error(ExitCode::wfp, code, L"Restore wfp-lock sublayer access control"));
        }
        return {};
    }
    if (code != FWP_E_SUBLAYER_NOT_FOUND)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Read wfp-lock sublayer"));
    }

    FWPM_SUBLAYER0 new_sublayer {};
    new_sublayer.subLayerKey = sublayer_key;
    new_sublayer.displayData.name = const_cast<wchar_t*>(L"wfp-lock Sublayer");
    new_sublayer.displayData.description =
        const_cast<wchar_t*>(L"Per-user TCP endpoint permits above default-deny blocks");
    new_sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    new_sublayer.providerKey = const_cast<GUID*>(&provider_key);
    new_sublayer.weight = sublayer_weight;
    code = FwpmSubLayerAdd0(engine,
        &new_sublayer,
        reinterpret_cast<PSECURITY_DESCRIPTOR>(const_cast<std::byte*>(object_descriptor.data())));
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Add wfp-lock sublayer"));
    }
    return {};
}

std::array<UINT8, 16> mapped_v6(std::uint32_t address_v4)
{
    return {0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0xff,
        0xff,
        static_cast<UINT8>(address_v4 >> 24),
        static_cast<UINT8>(address_v4 >> 16),
        static_cast<UINT8>(address_v4 >> 8),
        static_cast<UINT8>(address_v4)};
}

std::vector<Rule> build_rules(std::span<const detail::Endpoint> allowed)
{
    std::vector<Rule> rules;
    const auto permit = [&](const GUID& layer,
                            std::optional<std::uint32_t>
                                address_v4,
                            std::optional<std::array<UINT8, 16>>
                                address_v6,
                            std::uint16_t port)
    {
        rules.push_back(Rule {
            &layer,
            FWP_ACTION_PERMIT,
            permit_weight,
            static_cast<std::uint8_t>(IPPROTO_TCP),
            address_v4,
            address_v6,
            port
        });
    };
    for (const detail::Endpoint& endpoint : allowed)
    {
        if (endpoint.address_v4)
        {
            // Dual-stack sockets connect to IPv4 through the mapped IPv6 form.
            permit(FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                endpoint.address_v4,
                std::nullopt,
                endpoint.port);
            permit(FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                std::nullopt,
                mapped_v6(*endpoint.address_v4),
                endpoint.port);
        }
        else
        {
            permit(FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                std::nullopt,
                endpoint.address_v6,
                endpoint.port);
        }
    }

    for (const GUID* layer : {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6})
    {
        for (const std::uint8_t protocol :
            {static_cast<std::uint8_t>(IPPROTO_TCP), static_cast<std::uint8_t>(IPPROTO_UDP)})
        {
            rules.push_back(Rule {
                layer,
                FWP_ACTION_BLOCK,
                block_weight,
                protocol,
                std::nullopt,
                std::nullopt,
                std::nullopt
            });
        }
    }
    return rules;
}

Result<void> add_rule(HANDLE engine, const Rule& rule, FWP_BYTE_BLOB& user_descriptor,
    const std::vector<UINT8>& data, PSECURITY_DESCRIPTOR object_descriptor)
{
    std::array<FWPM_FILTER_CONDITION0, 4> conditions {};
    UINT32 count {};
    conditions[count].fieldKey = FWPM_CONDITION_ALE_USER_ID;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
    conditions[count].conditionValue.sd = &user_descriptor;
    ++count;

    conditions[count].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[count].matchType = FWP_MATCH_EQUAL;
    conditions[count].conditionValue.type = FWP_UINT8;
    conditions[count].conditionValue.uint8 = rule.protocol;
    ++count;

    FWP_BYTE_ARRAY16 address_v6 {};
    if (rule.address_v4)
    {
        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_UINT32;
        conditions[count].conditionValue.uint32 = *rule.address_v4;
        ++count;
    }
    else if (rule.address_v6)
    {
        std::memcpy(
            address_v6.byteArray16, rule.address_v6->data(), sizeof(address_v6.byteArray16));
        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        conditions[count].conditionValue.byteArray16 = &address_v6;
        ++count;
    }
    if (rule.port)
    {
        conditions[count].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conditions[count].matchType = FWP_MATCH_EQUAL;
        conditions[count].conditionValue.type = FWP_UINT16;
        conditions[count].conditionValue.uint16 = *rule.port;
        ++count;
    }

    FWP_VALUE0 weight {};
    weight.type = FWP_UINT64;
    weight.uint64 = const_cast<UINT64*>(&rule.weight);
    FWP_BYTE_BLOB provider_data {static_cast<UINT32>(data.size()), const_cast<UINT8*>(data.data())};
    FWPM_FILTER0 filter {};
    filter.displayData.name = const_cast<wchar_t*>(L"wfp-lock rule");
    filter.displayData.description =
        const_cast<wchar_t*>(L"Per-user TCP endpoint permit or default-deny rule");
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
    filter.providerKey = const_cast<GUID*>(&provider_key);
    filter.providerData = provider_data;
    filter.layerKey = *rule.layer;
    filter.subLayerKey = sublayer_key;
    filter.weight = weight;
    filter.numFilterConditions = count;
    filter.filterCondition = conditions.data();
    filter.action.type = rule.action;
    const DWORD code = FwpmFilterAdd0(engine, &filter, object_descriptor, nullptr);
    if (code != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, code, L"Add wfp-lock filter"));
    }
    return {};
}

Result<void> delete_user_filters(HANDLE engine, const std::vector<UINT8>& identity)
{
    std::vector<GUID> keys;
    auto enumerated = enumerate_filters(engine,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (is_owned_for(filter, identity))
            {
                keys.push_back(filter.filterKey);
            }
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    for (const GUID& key : keys)
    {
        const DWORD code = FwpmFilterDeleteByKey0(engine, &key);
        if (code != ERROR_SUCCESS)
        {
            return std::unexpected(win32_error(ExitCode::wfp, code, L"Delete wfp-lock filter"));
        }
    }
    return {};
}

Result<bool> remove_unused_infrastructure(HANDLE engine)
{
    bool referenced {};
    auto enumerated = enumerate_filters(engine,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            referenced = referenced || IsEqualGUID(filter.subLayerKey, sublayer_key) ||
                         (filter.providerKey && IsEqualGUID(*filter.providerKey, provider_key));
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    if (referenced)
    {
        return true;
    }
    DWORD code = FwpmSubLayerDeleteByKey0(engine, &sublayer_key);
    if (code != ERROR_SUCCESS && code != FWP_E_SUBLAYER_NOT_FOUND)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, code, L"Remove unused wfp-lock sublayer"));
    }
    code = FwpmProviderDeleteByKey0(engine, &provider_key);
    if (code != ERROR_SUCCESS && code != FWP_E_PROVIDER_NOT_FOUND)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, code, L"Remove unused wfp-lock provider"));
    }
    return false;
}

Result<void> clear_user_policy(PSID sid)
{
    auto infrastructure_lock = lock_shared_infrastructure();
    if (!infrastructure_lock)
    {
        return std::unexpected(infrastructure_lock.error());
    }
    auto engine = open_engine();
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    const DWORD begin = FwpmTransactionBegin0(engine->value, 0);
    if (begin != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::wfp, begin, L"Begin wfp-lock removal transaction"));
    }
    const auto identity = policy_identity(sid);
    auto deleted = delete_user_filters(engine->value, identity);
    if (!deleted)
    {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(deleted.error());
    }
    auto retained = remove_unused_infrastructure(engine->value);
    if (!retained)
    {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(retained.error());
    }
    const DWORD commit = FwpmTransactionCommit0(engine->value);
    if (commit != ERROR_SUCCESS)
    {
        FwpmTransactionAbort0(engine->value);
        return std::unexpected(
            win32_error(ExitCode::wfp, commit, L"Commit wfp-lock removal transaction"));
    }
    if (*retained)
    {
        auto descriptor = infrastructure_descriptor(engine->value);
        if (!descriptor)
        {
            return std::unexpected(descriptor.error());
        }
        auto refreshed = ensure_infrastructure(engine->value, *descriptor);
        if (!refreshed)
        {
            return std::unexpected(refreshed.error());
        }
    }
    auto enumeration = remove_filter_enumeration(engine->value, sid);
    if (!enumeration)
    {
        return std::unexpected(enumeration.error());
    }
    return {};
}

bool matches_rule(const FWPM_FILTER0& filter, const Rule& expected, const std::vector<UINT8>& data,
    const std::vector<std::byte>& user_sd)
{
    const UINT32 expected_conditions =
        2 + (expected.address_v4 || expected.address_v6 ? 1 : 0) + (expected.port ? 1 : 0);
    if (!filter.providerKey || !IsEqualGUID(*filter.providerKey, provider_key) ||
        !IsEqualGUID(filter.subLayerKey, sublayer_key) ||
        !IsEqualGUID(filter.layerKey, *expected.layer) ||
        filter.flags != FWPM_FILTER_FLAG_PERSISTENT || filter.action.type != expected.action ||
        filter.weight.type != FWP_UINT64 || !filter.weight.uint64 ||
        *filter.weight.uint64 != expected.weight ||
        filter.numFilterConditions != expected_conditions ||
        !same_blob(filter.providerData, data) || !matches_user(filter, user_sd))
    {
        return false;
    }
    const auto* protocol = find_condition(filter, FWPM_CONDITION_IP_PROTOCOL);
    if (!protocol || protocol->matchType != FWP_MATCH_EQUAL ||
        protocol->conditionValue.type != FWP_UINT8 ||
        protocol->conditionValue.uint8 != expected.protocol)
    {
        return false;
    }
    if (expected.address_v4 || expected.address_v6)
    {
        const auto* address = find_condition(filter, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        if (!address || address->matchType != FWP_MATCH_EQUAL)
        {
            return false;
        }
        if (expected.address_v4 && (address->conditionValue.type != FWP_UINT32 ||
                                       address->conditionValue.uint32 != *expected.address_v4))
        {
            return false;
        }
        if (expected.address_v6 && (address->conditionValue.type != FWP_BYTE_ARRAY16_TYPE ||
                                       !address->conditionValue.byteArray16 ||
                                       std::memcmp(address->conditionValue.byteArray16->byteArray16,
                                           expected.address_v6->data(),
                                           16) != 0))
        {
            return false;
        }
    }
    if (expected.port)
    {
        const auto* port = find_condition(filter, FWPM_CONDITION_IP_REMOTE_PORT);
        if (!port || port->matchType != FWP_MATCH_EQUAL ||
            port->conditionValue.type != FWP_UINT16 ||
            port->conditionValue.uint16 != *expected.port)
        {
            return false;
        }
    }
    return true;
}

Result<void> verify_policy(PSID sid, std::span<const detail::Endpoint> allowed)
{
    auto engine = open_engine(ExitCode::verification);
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    FWPM_PROVIDER0* provider {};
    const DWORD provider_result = FwpmProviderGetByKey0(engine->value, &provider_key, &provider);
    if (provider_result != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, provider_result, L"Read wfp-lock provider"));
    }
    const bool provider_properties_match = has_expected_provider_properties(*provider);
    FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
    if (!provider_properties_match)
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"wfp-lock provider does not match the policy"));
    }
    FWPM_SUBLAYER0* sublayer {};
    const DWORD sublayer_result = FwpmSubLayerGetByKey0(engine->value, &sublayer_key, &sublayer);
    if (sublayer_result != ERROR_SUCCESS)
    {
        return std::unexpected(
            win32_error(ExitCode::verification, sublayer_result, L"Read wfp-lock sublayer"));
    }
    const bool sublayer_properties_match = has_expected_sublayer_properties(*sublayer);
    if (!sublayer_properties_match)
    {
        const Error mismatch = unexpected_sublayer_properties(ExitCode::verification, *sublayer);
        FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));
        return std::unexpected(mismatch);
    }
    FwpmFreeMemory0(reinterpret_cast<void**>(&sublayer));

    auto user_sd = user_condition_descriptor(sid);
    if (!user_sd)
    {
        return std::unexpected(user_sd.error());
    }
    const std::array<PSID, 1> read_users {sid};
    auto filter_sd = wfp_object_descriptor(read_users);
    if (!filter_sd)
    {
        return std::unexpected(filter_sd.error());
    }
    auto provider_access = verify_provider_access(engine->value, sid);
    if (!provider_access)
    {
        return std::unexpected(provider_access.error());
    }
    auto sublayer_access = verify_sublayer_access(engine->value, sid);
    if (!sublayer_access)
    {
        return std::unexpected(sublayer_access.error());
    }
    const auto identity = policy_identity(sid);
    const auto expected = build_rules(allowed);
    std::vector<bool> matched(expected.size());
    std::size_t found {};
    auto enumerated = enumerate_filters(engine->value,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (!is_owned_for(filter, identity))
            {
                return {};
            }
            ++found;
            for (std::size_t index = 0; index < expected.size(); ++index)
            {
                if (!matched[index] && matches_rule(filter, expected[index], identity, *user_sd))
                {
                    auto filter_access =
                        verify_filter_access(engine->value, filter.filterKey, *filter_sd);
                    if (!filter_access)
                    {
                        return std::unexpected(filter_access.error());
                    }
                    matched[index] = true;
                    return {};
                }
            }
            return std::unexpected(error(ExitCode::verification,
                ERROR_INVALID_DATA,
                L"Installed policy contains an unexpected filter"));
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    if (found != expected.size() ||
        std::find(matched.begin(), matched.end(), false) != matched.end())
    {
        return std::unexpected(error(ExitCode::verification,
            ERROR_INVALID_DATA,
            L"Installed filters do not match the requested user and allow set"));
    }
    return {};
}

// The caller holds the shared-infrastructure lock.
Result<void> apply_policy(PSID sid, std::span<const detail::Endpoint> allowed)
{
    auto engine = open_engine();
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    auto user_sd = user_condition_descriptor(sid);
    if (!user_sd)
    {
        return std::unexpected(user_sd.error());
    }
    auto infrastructure_sd = infrastructure_descriptor(engine->value, sid);
    if (!infrastructure_sd)
    {
        return std::unexpected(infrastructure_sd.error());
    }
    const std::array<PSID, 1> read_users {sid};
    auto filter_sd = wfp_object_descriptor(read_users);
    if (!filter_sd)
    {
        return std::unexpected(filter_sd.error());
    }
    auto infrastructure = ensure_infrastructure(engine->value, *infrastructure_sd);
    if (!infrastructure)
    {
        return std::unexpected(infrastructure.error());
    }
    const DWORD begin = FwpmTransactionBegin0(engine->value, 0);
    if (begin != ERROR_SUCCESS)
    {
        return std::unexpected(win32_error(ExitCode::wfp, begin, L"Begin wfp-lock transaction"));
    }
    bool active = true;
    const auto abort = [&]
    {
        if (active)
        {
            FwpmTransactionAbort0(engine->value);
            active = false;
        }
    };
    const auto identity = policy_identity(sid);
    auto deleted = delete_user_filters(engine->value, identity);
    if (!deleted)
    {
        abort();
        return std::unexpected(deleted.error());
    }
    FWP_BYTE_BLOB user_blob {
        static_cast<UINT32>(user_sd->size()), reinterpret_cast<UINT8*>(user_sd->data())
    };
    for (const Rule& rule : build_rules(allowed))
    {
        auto added = add_rule(engine->value,
            rule,
            user_blob,
            identity,
            static_cast<PSECURITY_DESCRIPTOR>(filter_sd->data()));
        if (!added)
        {
            abort();
            return std::unexpected(added.error());
        }
    }
    const DWORD commit = FwpmTransactionCommit0(engine->value);
    if (commit != ERROR_SUCCESS)
    {
        abort();
        return std::unexpected(win32_error(ExitCode::wfp, commit, L"Commit wfp-lock transaction"));
    }
    active = false;
    auto enumeration = grant_filter_enumeration(engine->value, sid);
    if (!enumeration)
    {
        return std::unexpected(enumeration.error());
    }
    return {};
}

std::wstring address_text(const FWPM_FILTER_CONDITION0* address)
{
    if (!address)
    {
        return L"*";
    }
    wchar_t buffer[INET6_ADDRSTRLEN] {};
    if (address->conditionValue.type == FWP_UINT32)
    {
        const std::uint32_t network_address = htonl(address->conditionValue.uint32);
        std::array<UINT8, 4> bytes {};
        std::memcpy(bytes.data(), &network_address, sizeof(network_address));
        if (InetNtopW(AF_INET, bytes.data(), buffer, std::size(buffer)))
        {
            return buffer;
        }
    }
    else if (address->conditionValue.type == FWP_BYTE_ARRAY16_TYPE &&
             address->conditionValue.byteArray16 &&
             InetNtopW(AF_INET6,
                 address->conditionValue.byteArray16->byteArray16,
                 buffer,
                 std::size(buffer)))
    {
        return L"[" + std::wstring(buffer) + L"]";
    }
    return L"<invalid address>";
}

std::wstring protocol_text(const FWPM_FILTER_CONDITION0* protocol)
{
    if (!protocol || protocol->conditionValue.type != FWP_UINT8)
    {
        return L"<invalid protocol>";
    }
    if (protocol->conditionValue.uint8 == IPPROTO_TCP)
    {
        return L"tcp";
    }
    if (protocol->conditionValue.uint8 == IPPROTO_UDP)
    {
        return L"udp";
    }
    return L"<other protocol>";
}

Result<void> apply_command(std::wstring_view user, std::span<const detail::Endpoint> allowed)
{
    auto elevated = require_elevation();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    auto infrastructure_lock = lock_shared_infrastructure();
    if (!infrastructure_lock)
    {
        return std::unexpected(infrastructure_lock.error());
    }
    auto applied = apply_policy(sid->data(), allowed);
    if (!applied)
    {
        return std::unexpected(applied.error());
    }
    return verify_policy(sid->data(), allowed);
}

Result<void> verify_command(std::wstring_view user, std::span<const detail::Endpoint> allowed)
{
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    auto authorized = require_self_or_elevation(sid->data());
    if (!authorized)
    {
        return std::unexpected(authorized.error());
    }
    return verify_policy(sid->data(), allowed);
}

// Reconstructs the allow set from the account's installed permit filters, or
// returns nullopt when the account has no wfp-lock policy. An IPv4 entry's
// mapped IPv6 permit is part of that entry. The caller verifies the result
// after reapplying it.
Result<std::optional<std::vector<detail::Endpoint>>> installed_allow_set(HANDLE engine, PSID sid)
{
    const auto identity = policy_identity(sid);
    bool found {};
    std::vector<detail::Endpoint> endpoints;
    auto enumerated = enumerate_filters(engine,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (!is_owned_for(filter, identity))
            {
                return {};
            }
            found = true;
            if (filter.action.type != FWP_ACTION_PERMIT)
            {
                return {};
            }
            const auto* protocol = find_condition(filter, FWPM_CONDITION_IP_PROTOCOL);
            const auto* address = find_condition(filter, FWPM_CONDITION_IP_REMOTE_ADDRESS);
            const auto* port = find_condition(filter, FWPM_CONDITION_IP_REMOTE_PORT);
            const auto malformed = []
            {
                return std::unexpected(error(ExitCode::verification,
                    ERROR_INVALID_DATA,
                    L"Installed policy contains a malformed permit; replace it with apply"));
            };
            if (!protocol || protocol->conditionValue.type != FWP_UINT8 ||
                protocol->conditionValue.uint8 != IPPROTO_TCP || !address || !port ||
                port->conditionValue.type != FWP_UINT16)
            {
                return malformed();
            }
            detail::Endpoint endpoint;
            endpoint.port = port->conditionValue.uint16;
            if (IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4) &&
                address->conditionValue.type == FWP_UINT32)
            {
                endpoint.address_v4 = address->conditionValue.uint32;
            }
            else if (IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6) &&
                     address->conditionValue.type == FWP_BYTE_ARRAY16_TYPE &&
                     address->conditionValue.byteArray16)
            {
                std::array<UINT8, 16> bytes {};
                std::memcpy(bytes.data(), address->conditionValue.byteArray16->byteArray16, 16);
                constexpr std::array<UINT8, 12> mapped_prefix {
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
                };
                if (std::equal(mapped_prefix.begin(), mapped_prefix.end(), bytes.begin()))
                {
                    return {};
                }
                endpoint.address_v6 = bytes;
            }
            else
            {
                return malformed();
            }
            endpoints.push_back(endpoint);
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    if (!found)
    {
        return std::nullopt;
    }
    std::sort(endpoints.begin(), endpoints.end());
    endpoints.erase(std::unique(endpoints.begin(), endpoints.end()), endpoints.end());
    return endpoints;
}

enum class Change
{
    allow,
    revoke,
};

Result<void> change_command(
    std::wstring_view user, std::span<const detail::Endpoint> endpoints, Change change)
{
    auto elevated = require_elevation();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    // Hold the lock from reading the installed set until the new set is
    // committed, so that concurrent changes cannot overwrite each other.
    auto infrastructure_lock = lock_shared_infrastructure();
    if (!infrastructure_lock)
    {
        return std::unexpected(infrastructure_lock.error());
    }
    std::optional<std::vector<detail::Endpoint>> installed;
    {
        auto engine = open_engine();
        if (!engine)
        {
            return std::unexpected(engine.error());
        }
        auto read = installed_allow_set(engine->value, sid->data());
        if (!read)
        {
            return std::unexpected(read.error());
        }
        installed = std::move(*read);
    }
    if (!installed)
    {
        return std::unexpected(error(ExitCode::precondition,
            ERROR_NOT_FOUND,
            L"No wfp-lock policy is installed for " + std::wstring(user) + L"; use apply"));
    }
    std::vector<detail::Endpoint> allowed;
    if (change == Change::allow)
    {
        std::set_union(installed->begin(),
            installed->end(),
            endpoints.begin(),
            endpoints.end(),
            std::back_inserter(allowed));
        if (allowed.size() > max_allow_entries)
        {
            return std::unexpected(error(ExitCode::usage,
                ERROR_INVALID_PARAMETER,
                L"The policy would exceed " + std::to_wstring(max_allow_entries) +
                    L" endpoints"));
        }
    }
    else
    {
        std::set_difference(installed->begin(),
            installed->end(),
            endpoints.begin(),
            endpoints.end(),
            std::back_inserter(allowed));
    }
    auto applied = apply_policy(sid->data(), allowed);
    if (!applied)
    {
        return std::unexpected(applied.error());
    }
    return verify_policy(sid->data(), allowed);
}

Result<void> remove_command(std::wstring_view user)
{
    auto elevated = require_elevation();
    if (!elevated)
    {
        return std::unexpected(elevated.error());
    }
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    return clear_user_policy(sid->data());
}

Result<void> list_command(std::wstring_view user)
{
    auto sid = resolve_account_sid(user);
    if (!sid)
    {
        return std::unexpected(sid.error());
    }
    auto authorized = require_self_or_elevation(sid->data());
    if (!authorized)
    {
        return std::unexpected(authorized.error());
    }
    auto text = sid_string(sid->data());
    if (!text)
    {
        return std::unexpected(text.error());
    }
    auto engine = open_engine();
    if (!engine)
    {
        return std::unexpected(engine.error());
    }
    const auto identity = policy_identity(sid->data());
    std::wcout << L"wfp-lock filters for " << *text << L":\n";
    std::size_t count {};
    auto enumerated = enumerate_filters(engine->value,
        [&](const FWPM_FILTER0& filter) -> Result<void>
        {
            if (!is_owned_for(filter, identity))
            {
                return {};
            }
            ++count;
            const auto* protocol = find_condition(filter, FWPM_CONDITION_IP_PROTOCOL);
            const auto* address = find_condition(filter, FWPM_CONDITION_IP_REMOTE_ADDRESS);
            const auto* port = find_condition(filter, FWPM_CONDITION_IP_REMOTE_PORT);
            const wchar_t* layer = IsEqualGUID(filter.layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4)
                                       ? L"ALE_AUTH_CONNECT_V4"
                                       : L"ALE_AUTH_CONNECT_V6";
            std::wcout << L"[" << filter.filterId << L"] "
                       << (filter.action.type == FWP_ACTION_PERMIT ? L"permit " : L"block ")
                       << protocol_text(protocol) << L" " << address_text(address);
            if (port && port->conditionValue.type == FWP_UINT16)
            {
                std::wcout << L":" << port->conditionValue.uint16;
            }
            std::wcout << L" at " << layer << L"\n";
            return {};
        });
    if (!enumerated)
    {
        return std::unexpected(enumerated.error());
    }
    if (count == 0)
    {
        std::wcout << L"(none)\n";
    }
    return {};
}

// Parses a comma-separated endpoint list into a sorted set without repeats.
Result<std::vector<detail::Endpoint>> parse_endpoint_list(std::wstring_view list)
{
    std::vector<detail::Endpoint> endpoints;
    for (;;)
    {
        const auto comma = list.find(L',');
        const auto item = list.substr(0, comma);
        auto endpoint = detail::parse_endpoint(item);
        if (!endpoint)
        {
            return std::unexpected(error(ExitCode::usage,
                ERROR_INVALID_DATA,
                L"Invalid endpoint: '" + std::wstring(item) +
                    L"'; expected <ipv4>:<port> or [<ipv6>]:<port>"));
        }
        endpoints.push_back(*endpoint);
        if (endpoints.size() > max_allow_entries)
        {
            return std::unexpected(error(ExitCode::usage,
                ERROR_INVALID_PARAMETER,
                L"At most " + std::to_wstring(max_allow_entries) + L" endpoints are accepted"));
        }
        if (comma == std::wstring_view::npos)
        {
            break;
        }
        list.remove_prefix(comma + 1);
    }
    std::sort(endpoints.begin(), endpoints.end());
    endpoints.erase(std::unique(endpoints.begin(), endpoints.end()), endpoints.end());
    return endpoints;
}

// apply and verify: --user <account> [--allow <endpoints>]
// allow and revoke: --user <account> <endpoints>
Result<PolicyInput> parse_policy_input(
    std::span<const std::wstring_view> arguments, bool endpoints_required)
{
    const bool has_allow =
        !endpoints_required && arguments.size() == 5 && arguments[3] == L"--allow";
    const bool has_list = endpoints_required && arguments.size() == 4;
    const bool no_list = !endpoints_required && arguments.size() == 3;
    if (!(has_allow || has_list || no_list) || arguments[1] != L"--user" || arguments[2].empty())
    {
        return std::unexpected(error(ExitCode::usage,
            ERROR_INVALID_PARAMETER,
            endpoints_required ? L"Expected --user <account> <endpoints>"
                               : L"Expected --user <account> [--allow <endpoints>]"));
    }
    PolicyInput input {std::wstring(arguments[2]), {}};
    if (no_list)
    {
        return input;
    }
    auto endpoints = parse_endpoint_list(arguments.back());
    if (!endpoints)
    {
        return std::unexpected(endpoints.error());
    }
    input.allowed = std::move(*endpoints);
    return input;
}

void print_usage()
{
    std::wcerr << L"wfp-lock.exe - Restrict a user's outbound traffic to allowed TCP endpoints.\n"
               << L"Copyright (C) 2026 Florian Mücke\n"
               << L"This is free software - you are welcome to redistribute it under the terms\n"
               << L"of the GNU General Public License version 3; see LICENSE for details.\n"
               //<< L"This program comes with ABSOLUTELY NO WARRANTY.\n"
               << L"\nThe policy permits the selected account's TCP connections to the allowed\n"
               << L"endpoints and blocks its other outbound TCP and UDP traffic.\n"
               << L"\nUsage:\n"
               << L"  wfp-lock.exe apply  --user <account> [--allow <endpoints>]\n"
               << L"  wfp-lock.exe verify --user <account> [--allow <endpoints>]\n"
               << L"  wfp-lock.exe allow  --user <account> <endpoints>\n"
               << L"  wfp-lock.exe revoke --user <account> <endpoints>\n"
               << L"  wfp-lock.exe remove --user <account>\n"
               << L"  wfp-lock.exe list   --user <account>\n"
               << L"\nCommands:\n"
               << L"  apply   Replace the policy with the given endpoints and verify it.\n"
               << L"  verify  Check that the installed policy has exactly these endpoints.\n"
               << L"  allow   Add endpoints to the installed policy and verify it.\n"
               << L"  revoke  Remove endpoints from the installed policy and verify it.\n"
               << L"  remove  Remove this tool's policy.\n"
               << L"  list    List this tool's filters.\n"
               << L"\nOptions:\n"
               << L"  --user <account>     Local Windows account to which the policy applies.\n"
               << L"  --allow <endpoints>  Endpoints to permit. Without --allow, all outbound\n"
               << L"                       TCP and UDP is blocked.\n"
               << L"\n<endpoints> is a comma-separated list of <ipv4>:<port> or [<ipv6>]:<port>.\n"
               << L"A policy holds at most 32 endpoints. IPv4 also permits its ::ffff: form.\n"
               << L"\napply, allow, revoke, and remove require an elevated Administrator session."
                  L"\nA managed standard account may list or verify only its own policy.\n"
               << std::endl;
}

int finish(Result<void> result, std::wstring_view success_message)
{
    if (!result)
    {
        std::wcerr << L"Error: " << result.error().message << L'\n';
        return static_cast<int>(result.error().exit_code);
    }
    std::wcout << success_message << L'\n';
    return static_cast<int>(ExitCode::success);
}

} // namespace

int run(std::span<const std::wstring_view> arguments)
{
    if (arguments.empty())
    {
        print_usage();
        return static_cast<int>(ExitCode::usage);
    }
    if (arguments[0] == L"apply" || arguments[0] == L"verify")
    {
        auto input = parse_policy_input(arguments, false);
        if (!input)
        {
            print_usage();
            std::wcerr << L"Error: " << input.error().message << L'\n';
            return static_cast<int>(input.error().exit_code);
        }
        if (arguments[0] == L"apply")
        {
            return finish(apply_command(input->user, input->allowed),
                L"wfp-lock policy applied and verified.");
        }
        return finish(verify_command(input->user, input->allowed),
            L"wfp-lock policy matches the requested user and allow set.");
    }
    if (arguments[0] == L"allow" || arguments[0] == L"revoke")
    {
        auto input = parse_policy_input(arguments, true);
        if (!input)
        {
            print_usage();
            std::wcerr << L"Error: " << input.error().message << L'\n';
            return static_cast<int>(input.error().exit_code);
        }
        if (arguments[0] == L"allow")
        {
            return finish(change_command(input->user, input->allowed, Change::allow),
                L"wfp-lock endpoints allowed; policy verified.");
        }
        return finish(change_command(input->user, input->allowed, Change::revoke),
            L"wfp-lock endpoints revoked; policy verified.");
    }
    if (arguments[0] == L"remove" || arguments[0] == L"list")
    {
        if (arguments.size() != 3 || arguments[1] != L"--user" || arguments[2].empty())
        {
            print_usage();
            return static_cast<int>(ExitCode::usage);
        }
        if (arguments[0] == L"remove")
        {
            return finish(remove_command(arguments[2]), L"wfp-lock policy removed.");
        }
        return finish(list_command(arguments[2]), L"wfp-lock filters listed.");
    }
    print_usage();
    return static_cast<int>(ExitCode::usage);
}

} // namespace wfp_lock
