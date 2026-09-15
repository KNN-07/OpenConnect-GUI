/* SPDX-License-Identifier: GPL-3.0-only
 * Package-only ACL guard, embedded in the elevated NSIS installer. It never
 * accepts a filesystem path, starts a service, or changes network/user state.
 */
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <wchar.h>

#define CAP 32768
static BYTE admin_sid[SECURITY_MAX_SID_SIZE], system_sid[SECURITY_MAX_SID_SIZE];
static const DWORD writes = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA |
    FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER |
    GENERIC_WRITE | GENERIC_ALL;

static int trusted_sid(PSID sid) {
    return sid && (EqualSid(sid, admin_sid) || EqualSid(sid, system_sid));
}

static int trusted(const wchar_t *path) {
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    int ok = 0;
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return 0;
    if (GetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, NULL, &dacl, NULL, &descriptor) != ERROR_SUCCESS) return 0;
    if (!trusted_sid(owner) || !dacl) goto out;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        ACE_HEADER *header = NULL;
        if (!GetAce(dacl, i, (void **)&header)) goto out;
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) goto out;
        ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)header;
        if ((ace->Mask & writes) && !trusted_sid((PSID)&ace->SidStart)) goto out;
    }
    ok = 1;
out:
    LocalFree(descriptor);
    return ok;
}

static int descriptor_for(int state, PSECURITY_DESCRIPTOR *descriptor) {
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
        state ? L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" :
                L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
        SDDL_REVISION_1, descriptor, NULL) != 0;
}

static int create_root(const wchar_t *path, int state) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!descriptor_for(state, &descriptor)) return 0;
    SECURITY_ATTRIBUTES attributes = { sizeof(attributes), descriptor, FALSE };
    int created = CreateDirectoryW(path, &attributes) != 0;
    DWORD error = GetLastError();
    LocalFree(descriptor);
    return created || (error == ERROR_ALREADY_EXISTS && trusted(path));
}

static int protect(const wchar_t *path) {
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PSID owner = NULL;
    PACL dacl = NULL;
    BOOL defaulted = FALSE, present = FALSE;
    if (!descriptor_for(0, &descriptor)) return 0;
    int ok = GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) &&
        GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present &&
        SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            owner, NULL, dacl, NULL) == ERROR_SUCCESS;
    LocalFree(descriptor);
    return ok;
}

static int walk(const wchar_t *path, int apply, unsigned depth) {
    if (depth > 32) return 0;
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return 0;
    /* prepare validates every old file before installed code may run; protect
     * acts only after that barrier and after NSIS has copied its own payload. */
    if (!(apply ? protect(path) : trusted(path))) return 0;
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) return 1;
    wchar_t *child = HeapAlloc(GetProcessHeap(), 0, CAP * sizeof(wchar_t));
    if (!child) return 0;
    int length = _snwprintf(child, CAP, L"%ls\\*", path);
    if (length < 0 || length >= CAP) { HeapFree(GetProcessHeap(), 0, child); return 0; }
    WIN32_FIND_DATAW entry;
    HANDLE search = FindFirstFileW(child, &entry);
    if (search == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        HeapFree(GetProcessHeap(), 0, child);
        return error == ERROR_FILE_NOT_FOUND;
    }
    int ok = 1;
    do {
        if (!wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L"..")) continue;
        length = _snwprintf(child, CAP, L"%ls\\%ls", path, entry.cFileName);
        if (length < 0 || length >= CAP || !walk(child, apply, depth + 1)) { ok = 0; break; }
    } while (FindNextFileW(search, &entry));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES) ok = 0;
    FindClose(search);
    HeapFree(GetProcessHeap(), 0, child);
    return ok;
}

static int folder(REFKNOWNFOLDERID id, const wchar_t *suffix, wchar_t *output) {
    PWSTR base = NULL;
    if (FAILED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, NULL, &base))) return 0;
    int length = _snwprintf(output, CAP, L"%ls\\%ls", base, suffix);
    CoTaskMemFree(base);
    return length >= 0 && length < CAP;
}

int wmain(int argc, wchar_t **argv) {
    DWORD size = sizeof(admin_sid);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin_sid, &size)) return 1;
    size = sizeof(system_sid);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, system_sid, &size)) return 1;
    BOOL administrator = FALSE;
    if (!CheckTokenMembership(NULL, admin_sid, &administrator) || !administrator) return 1;
    if (argc != 2 || (wcscmp(argv[1], L"prepare") && wcscmp(argv[1], L"protect"))) return 2;
    int apply = !wcscmp(argv[1], L"protect");
    wchar_t *root = HeapAlloc(GetProcessHeap(), 0, CAP * sizeof(wchar_t));
    if (!root) return 1;
    int ok = folder(&FOLDERID_ProgramFiles, L"OpenConnect GUI", root) &&
        create_root(root, 0) && trusted(root) && walk(root, apply, 0);
    if (ok && apply) {
        ok = folder(&FOLDERID_ProgramData, L"OpenConnectGUI", root) &&
            create_root(root, 1) && walk(root, 0, 0);
    }
    HeapFree(GetProcessHeap(), 0, root);
    if (!ok) fwprintf(stderr, L"Install/state paths are not protected; no existing service helper was trusted. Preserve files and reconcile ownership.\n");
    return ok ? 0 : 1;
}
