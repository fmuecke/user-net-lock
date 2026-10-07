// Copyright (C) 2026 Florian Mücke
// SPDX-License-Identifier: GPL-3.0-or-later
// Project: https://github.com/fmuecke/wfp-lock.git

#pragma once

#include <windows.h>

namespace wfp_lock::detail
{

// WFP policy objects are administrative settings. P protects this DACL from
// inherited engine ACEs. Each managed account receives a separate read-only
// ACE at installation time; only SYSTEM and Administrators receive full
// control.
inline constexpr wchar_t administrative_wfp_object_dacl_sddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";

bool same_access_control_descriptor(PSECURITY_DESCRIPTOR actual, PSECURITY_DESCRIPTOR expected);

bool has_protected_dacl(PSECURITY_DESCRIPTOR descriptor);

} // namespace wfp_lock::detail
