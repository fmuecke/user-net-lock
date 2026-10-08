// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// Project: https://github.com/fmuecke/wfp-lock.git

#include "endpoint.h"
#include "wfp_object_access.h"
#include "wfp_lock.h"

#include <cstdlib>
#include <cwchar>
#include <iostream>
#include <memory>
#include <sddl.h>
#include <string>
#include <string_view>

namespace
{

int failures = 0;

void check(bool condition, std::string_view message)
{
    if (!condition)
    {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void cli_tests()
{
    check(wfp_lock::run({}) == static_cast<int>(wfp_lock::ExitCode::usage),
        "empty CLI is a usage error");

    constexpr std::wstring_view unknown[] = {L"unknown"};
    check(wfp_lock::run(unknown) == static_cast<int>(wfp_lock::ExitCode::usage),
        "unknown command is a usage error");

    // Every case is rejected during parsing, before any WFP state is read.
    for (const auto command : {L"apply", L"verify"})
    {
        const std::wstring_view missing_user[] = {command, L"--allow", L"127.0.0.1:8080"};
        check(wfp_lock::run(missing_user) == static_cast<int>(wfp_lock::ExitCode::usage),
            "apply and verify require a user");

        const std::wstring_view empty_user[] = {command, L"--user", L""};
        check(wfp_lock::run(empty_user) == static_cast<int>(wfp_lock::ExitCode::usage),
            "apply and verify reject an empty user");

        const std::wstring_view missing_value[] = {command, L"--user", L"AgentSandbox", L"--allow"};
        check(wfp_lock::run(missing_value) == static_cast<int>(wfp_lock::ExitCode::usage),
            "--allow requires a value");

        for (const auto invalid_list : {L"localhost:8080",
                 L"",
                 L"127.0.0.1:8080,",
                 L",127.0.0.1:8080",
                 L"127.0.0.1:8080,,[::1]:8080",
                 L"127.0.0.1:8080, [::1]:8080",
                 L"127.0.0.1:8080;[::1]:8080"})
        {
            const std::wstring_view invalid_value[] = {
                command, L"--user", L"AgentSandbox", L"--allow", invalid_list};
            check(wfp_lock::run(invalid_value) == static_cast<int>(wfp_lock::ExitCode::usage),
                "an invalid --allow list is a usage error");
        }

        const std::wstring_view repeated_allow[] = {command,
            L"--user",
            L"AgentSandbox",
            L"--allow",
            L"127.0.0.1:8080",
            L"--allow",
            L"[::1]:8080"};
        check(wfp_lock::run(repeated_allow) == static_cast<int>(wfp_lock::ExitCode::usage),
            "--allow may be given only once");

        const std::wstring_view removed_port[] = {
            command, L"--user", L"AgentSandbox", L"--port", L"8080"};
        check(wfp_lock::run(removed_port) == static_cast<int>(wfp_lock::ExitCode::usage),
            "--port is no longer accepted");

        const std::wstring_view config_file[] = {command, L"--config", L"policy.ini"};
        check(wfp_lock::run(config_file) == static_cast<int>(wfp_lock::ExitCode::usage),
            "configuration files are not accepted");

        std::wstring too_many_list;
        for (int port = 1; port <= 33; ++port)
        {
            too_many_list += (port == 1 ? L"" : L",") + std::wstring(L"127.0.0.1:") +
                             std::to_wstring(port);
        }
        const std::wstring_view too_many[] = {
            command, L"--user", L"AgentSandbox", L"--allow", too_many_list};
        check(wfp_lock::run(too_many) == static_cast<int>(wfp_lock::ExitCode::usage),
            "more than 32 --allow endpoints are rejected");
    }

    for (const auto command : {L"allow", L"revoke"})
    {
        const std::wstring_view missing_list[] = {command, L"--user", L"AgentSandbox"};
        check(wfp_lock::run(missing_list) == static_cast<int>(wfp_lock::ExitCode::usage),
            "allow and revoke require an endpoint list");

        const std::wstring_view option_form[] = {
            command, L"--user", L"AgentSandbox", L"--allow", L"10.1.2.3:5432"};
        check(wfp_lock::run(option_form) == static_cast<int>(wfp_lock::ExitCode::usage),
            "allow and revoke take the endpoint list as a positional argument");

        const std::wstring_view empty_user[] = {command, L"--user", L"", L"10.1.2.3:5432"};
        check(wfp_lock::run(empty_user) == static_cast<int>(wfp_lock::ExitCode::usage),
            "allow and revoke reject an empty user");

        const std::wstring_view invalid_list[] = {
            command, L"--user", L"AgentSandbox", L"10.1.2.3:5432,"};
        check(wfp_lock::run(invalid_list) == static_cast<int>(wfp_lock::ExitCode::usage),
            "allow and revoke reject an invalid endpoint list");
    }

    constexpr std::wstring_view remove_config[] = {L"remove", L"--config", L"policy.ini"};
    check(wfp_lock::run(remove_config) == static_cast<int>(wfp_lock::ExitCode::usage),
        "remove does not accept a configuration file");

    constexpr std::wstring_view missing_remove_user[] = {L"remove"};
    check(wfp_lock::run(missing_remove_user) == static_cast<int>(wfp_lock::ExitCode::usage),
        "remove requires a user");

    constexpr std::wstring_view invalid_list[] = {L"list"};
    check(wfp_lock::run(invalid_list) == static_cast<int>(wfp_lock::ExitCode::usage),
        "list requires a user");

    constexpr std::wstring_view removed_clear[] = {L"clear", L"--user", L"AgentSandbox"};
    check(wfp_lock::run(removed_clear) == static_cast<int>(wfp_lock::ExitCode::usage),
        "clear is no longer an alias for remove");
}

// A deliberately invalid local-account name keeps these CLI checks out of WFP.
void endpoint_limit_tests()
{
    std::wstring list;
    for (int port = 1; port <= 32; ++port)
    {
        list += (port == 1 ? L"" : L",") + std::wstring(L"127.0.0.1:") + std::to_wstring(port);
    }
    list += L",127.0.0.1:00001";
    const std::wstring_view arguments[] = {L"verify", L"--user",
        L".\\wfp-lock-endpoint-limit-invalid-account", L"--allow", list};
    check(wfp_lock::run(arguments) == static_cast<int>(wfp_lock::ExitCode::precondition),
        "32 unique endpoints plus a duplicate pass parsing and reach account validation");
}

void endpoint_parsing_tests()
{
    using wfp_lock::detail::parse_endpoint;

    const auto v4 = parse_endpoint(L"10.1.2.3:5432");
    check(v4 && v4->address_v4 == 0x0a010203u && !v4->address_v6 && v4->port == 5432,
        "IPv4 endpoint is parsed in host byte order");

    const auto v6 = parse_endpoint(L"[2001:db8::1]:443");
    check(v6 && !v6->address_v4 && v6->address_v6 && (*v6->address_v6)[0] == 0x20 &&
              (*v6->address_v6)[15] == 1 && v6->port == 443,
        "bracketed IPv6 endpoint is parsed");

    check(parse_endpoint(L"127.0.0.1:65535").has_value(), "loopback and port 65535 are accepted");
    check(parse_endpoint(L"[::1]:1").has_value(), "IPv6 loopback and port 1 are accepted");
    check(parse_endpoint(L"10.1.2.3:5432") == parse_endpoint(L"10.1.2.3:05432"),
        "equal endpoints compare equal");

    for (const auto invalid : {
             L"",
             L"10.1.2.3",
             L"10.1.2.3:",
             L"10.1.2.3:0",
             L"10.1.2.3:65536",
             L"10.1.2.3:123456",
             L"10.1.2.3:+80",
             L"10.1.2.3:80 ",
             L" 10.1.2.3:80",
             L"10.1.2:80",
             L"localhost:80",
             L"db.example.com:5432",
             L"0.0.0.0:80",
             L"255.255.255.255:80",
             L"224.0.0.1:80",
             L"239.255.255.250:1900",
             L"[10.1.2.3]:80",
             L"::1:80",
             L"[::1]",
             L"[::1]:",
             L"[::]:80",
             L"[ff02::1]:80",
             L"[::ffff:10.1.2.3]:80",
             L"[fe80::1%3]:80",
             L"[2001:db8::1:80",
         })
    {
        check(!parse_endpoint(invalid).has_value(), "invalid --allow value is rejected");
    }
    check(!parse_endpoint(std::wstring_view(L"10.1.2.3\0x:80", 13)).has_value(),
        "embedded NUL is rejected");
}

PSECURITY_DESCRIPTOR descriptor_from_sddl(PCWSTR sddl)
{
    PSECURITY_DESCRIPTOR descriptor {};
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &descriptor, nullptr))
    {
        check(false, "test security descriptor can be created");
    }
    return descriptor;
}

void wfp_object_access_control_tests()
{
    // P prevents inherited WFP engine ACEs from widening the administrative
    // baseline. A managed account receives a separate, read-only ACE.
    constexpr wchar_t expected_sddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    check(std::wcscmp(wfp_lock::detail::administrative_wfp_object_dacl_sddl, expected_sddl) == 0,
        "WFP objects retain SYSTEM and Administrators full control baseline");

    PSECURITY_DESCRIPTOR expected =
        descriptor_from_sddl(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)");
    std::unique_ptr<void, decltype(&LocalFree)> expected_memory(expected, LocalFree);
    if (!expected)
    {
        return;
    }
    check(wfp_lock::detail::same_access_control_descriptor(expected, expected),
        "the expected WFP object DACL matches itself");
    check(wfp_lock::detail::has_protected_dacl(expected),
        "the expected WFP object DACL is protected");

    PSECURITY_DESCRIPTOR unprotected =
        descriptor_from_sddl(L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)");
    std::unique_ptr<void, decltype(&LocalFree)> unprotected_memory(unprotected, LocalFree);
    if (!unprotected)
    {
        return;
    }
    check(!wfp_lock::detail::has_protected_dacl(unprotected),
        "an unprotected WFP object DACL is rejected");

    // A managed account may read status, but no standard account may receive
    // WFP write, delete, or DACL-changing rights.
    PSECURITY_DESCRIPTOR broader = descriptor_from_sddl(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GW;;;AU)");
    std::unique_ptr<void, decltype(&LocalFree)> broader_memory(broader, LocalFree);
    if (!broader)
    {
        return;
    }
    check(!wfp_lock::detail::same_access_control_descriptor(broader, expected),
        "a WFP object DACL that grants a managed account write access is rejected");
}

} // namespace

int main()
{
    cli_tests();
    endpoint_parsing_tests();
    endpoint_limit_tests();
    wfp_object_access_control_tests();
    if (failures != 0)
    {
        std::cerr << failures << " test(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "All tests passed\n";
    return EXIT_SUCCESS;
}
