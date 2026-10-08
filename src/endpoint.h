// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// Project: https://github.com/fmuecke/wfp-lock.git

#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <optional>
#include <string_view>

namespace wfp_lock::detail
{

// One permitted TCP destination. Exactly one address is set; the IPv4 address
// is in host byte order, as WFP expects it.
struct Endpoint
{
    std::optional<std::uint32_t> address_v4;
    std::optional<std::array<std::uint8_t, 16>> address_v6;
    std::uint16_t port {};

    auto operator<=>(const Endpoint&) const = default;
};

// Parses <ipv4>:<port> or [<ipv6>]:<port>. Rejects hostnames, zone IDs,
// IPv4-mapped IPv6, unspecified, multicast, and broadcast addresses, and
// port 0.
std::optional<Endpoint> parse_endpoint(std::wstring_view text);

} // namespace wfp_lock::detail
