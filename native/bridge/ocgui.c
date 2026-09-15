/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 OpenConnect GUI contributors
 * Compiled into libopenconnect with its own toolchain, never with Rust/MSVC.
 */
#include "config.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#endif
#include "openconnect-internal.h"
#include "ocgui.h"
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#if OPENCONNECT_API_VERSION_MAJOR != 5 || OPENCONNECT_API_VERSION_MINOR != 9
#error The bridge requires the pinned OpenConnect 9.21 / API 5.9 source
#endif
#ifndef HAVE_HPKE_SUPPORT
#error Cisco external SSO requires GnuTLS HKDF, hogweed/nettle and GMP
#endif
#ifndef OPENCONNECT_GNUTLS
#error The bundled engine requires GnuTLS
#endif

unsigned int ocgui_bridge_abi(void) { return 4; }
unsigned int ocgui_api_version_major(void) { return OPENCONNECT_API_VERSION_MAJOR; }
unsigned int ocgui_api_version_minor(void) { return OPENCONNECT_API_VERSION_MINOR; }
int ocgui_has_hpke(void) { return 1; } /* Enforced by the compile-time guard. */

int ocgui_set_gp_browser_mode(struct openconnect_info *vpninfo, int mode)
{
    if (!vpninfo || (mode != 0 && mode != 1))
        return -EINVAL;
    vpninfo->ocgui_gp_browser_configured = 1;
    vpninfo->ocgui_gp_browser_mode = mode;
    return 0;
}

int ocgui_gp_external_allowed(struct openconnect_info *vpninfo)
{
    return vpninfo && vpninfo->ocgui_gp_phase ?
        vpninfo->ocgui_gp_external_allowed : -1;
}

int ocgui_gp_auth_phase(struct openconnect_info *vpninfo)
{
    return vpninfo ? vpninfo->ocgui_gp_phase : 0;
}

int ocgui_gp_retry_embedded(struct openconnect_info *vpninfo)
{
    if (!vpninfo)
        return -EINVAL;
    if (vpninfo->ocgui_gp_retry_used || vpninfo->ocgui_gp_retry_requested)
        return -EALREADY;
    if (!vpninfo->ocgui_gp_phase || !vpninfo->ocgui_gp_retry_eligible ||
        !vpninfo->ocgui_gp_browser_configured ||
        vpninfo->ocgui_gp_requested_mode != 1 ||
        vpninfo->ocgui_gp_external_allowed != 0)
        return -EPERM;
    vpninfo->ocgui_gp_retry_requested = 1;
    return 0;
}

/* Deliberately discard native constructor/hash diagnostics: the verifier
 * returns fixed reasons, never certificate contents or caller input. */
static void browser_verify_progress(void *context, int level, const char *format, ...)
{
    (void)context;
    (void)level;
    (void)format;
}

static int browser_cert_hash(struct openconnect_info *vpninfo)
{
    gnutls_pubkey_t key;
    gnutls_datum_t der = { NULL, 0 };
    size_t size;
    int result;
    /* Exactly gnutls.c::set_peer_cert_hash: DER SubjectPublicKeyInfo,
     * not the complete certificate or the algorithm's raw key bytes. */
    result = gnutls_pubkey_init(&key);
    if (result < 0)
        return result;
    result = gnutls_pubkey_import_x509(key, vpninfo->peer_cert, 0);
    if (result >= 0)
        result = gnutls_pubkey_export2(key, GNUTLS_X509_FMT_DER, &der);
    gnutls_pubkey_deinit(key);
    if (result < 0)
        return result;
    size = sizeof(vpninfo->peer_cert_sha256_raw);
    result = gnutls_fingerprint(GNUTLS_DIG_SHA256, &der,
                               vpninfo->peer_cert_sha256_raw, &size);
    if (result >= 0) {
        size = sizeof(vpninfo->peer_cert_sha1_raw);
        result = gnutls_fingerprint(GNUTLS_DIG_SHA1, &der,
                                   vpninfo->peer_cert_sha1_raw, &size);
    }
    gnutls_free(der.data);
    return result;
}

int ocgui_verify_browser_chain(const struct oc_cert *chain, unsigned count,
                               const char *host, const char *cafile,
                               const char *pin, char *fingerprint,
                               size_t fingerprint_size, char *reason,
                               size_t reason_size, unsigned *status)
{
    gnutls_x509_crt_t certs[16] = { NULL };
    gnutls_x509_trust_list_t roots = NULL;
    struct openconnect_info *temporary = NULL;
    gnutls_typed_vdata_st purpose = {
        .type = GNUTLS_DT_KEY_PURPOSE_OID,
        .data = (unsigned char *)GNUTLS_KP_TLS_WWW_SERVER,
        .size = 0
    };
    char normalized_host[254];
    const char *hash, *message = "Invalid browser certificate input";
    size_t total = 0, host_size, pin_size;
    unsigned i, key_usage;
    int result = -EINVAL, error = 0;

    if (fingerprint && fingerprint_size)
        fingerprint[0] = '\0';
    if (reason && reason_size)
        reason[0] = '\0';
    if (status)
        *status = GNUTLS_CERT_INVALID;
    if (!fingerprint || !reason || !reason_size || !status)
        return -EINVAL;
    if (fingerprint_size < 56) {
        result = -ENOSPC;
        goto out;
    }
    if (!chain || !count || count > 16 || !host || !*host ||
        (host_size = strnlen(host, sizeof(normalized_host))) >= sizeof(normalized_host) ||
        (cafile && (!*cafile || strnlen(cafile, 4097) > 4096)) ||
        (pin && strnlen(pin, 129) > 128))
        goto out;
    memcpy(normalized_host, host, host_size + 1);
    if (normalized_host[0] == '[' && host_size > 2 &&
        normalized_host[host_size - 1] == ']') {
        memmove(normalized_host, normalized_host + 1, host_size - 2);
        normalized_host[host_size - 2] = '\0';
    }
    for (i = 0; i < count; ++i) {
        if (!chain[i].der_data || chain[i].der_len <= 0 ||
            (size_t)chain[i].der_len > 1048576 - total)
            goto out;
        total += chain[i].der_len;
    }
    temporary = openconnect_vpninfo_new("OpenConnect-GUI browser verifier",
                                      NULL, NULL, NULL, browser_verify_progress, NULL);
    if (!temporary) {
        result = -ENOMEM;
        message = "Cannot allocate native certificate verifier";
        goto out;
    }
    for (i = 0; i < count; ++i) {
        gnutls_datum_t der = { chain[i].der_data, (unsigned)chain[i].der_len };
        error = gnutls_x509_crt_init(&certs[i]);
        if (error < 0)
            goto runtime_error;
        error = gnutls_x509_crt_import(certs[i], &der, GNUTLS_X509_FMT_DER);
        if (error < 0) {
            result = error == GNUTLS_E_MEMORY_ERROR ? -ENOMEM : -EINVAL;
            message = "Cannot parse browser certificate DER";
            goto out;
        }
        if (i == 0) {
            /* Transfer the imported leaf, never the borrowed DER, to the
             * native context; its destructor releases this one certificate. */
            temporary->peer_cert = certs[0];
            error = browser_cert_hash(temporary);
            if (error < 0)
                goto runtime_error;
            hash = openconnect_get_peer_cert_hash(temporary);
            if (!hash) {
                result = -ENOMEM;
                message = "Cannot allocate certificate fingerprint";
                goto out;
            }
            snprintf(fingerprint, fingerprint_size, "%s", hash);
        }
    }
    if (pin) {
        pin_size = strlen(pin);
        /* Upstream accepts prefixes; this boundary accepts complete hashes
         * only, including the historical whole-certificate SHA1 format. */
        if (!((pin_size == 55 && !strncmp(pin, "pin-sha256:", 11)) ||
              (pin_size == 71 && !strncmp(pin, "sha256:", 7)) ||
              (pin_size == 45 && !strncmp(pin, "sha1:", 5)) ||
              (pin_size == 40 && !strchr(pin, ':'))))
            goto out;
        result = openconnect_check_peer_cert_hash(temporary, pin);
        if (!result)
            *status = 0;
        message = result == 0 ? "Certificate matches saved pin" :
                  result == 1 ? "Certificate does not match saved pin" :
                  "Cannot compare certificate pin";
        goto out;
    }
    error = gnutls_x509_trust_list_init(&roots, 0);
    if (error < 0)
        goto runtime_error;
    error = gnutls_x509_trust_list_add_system_trust(roots, 0, 0);
    if (error < 0)
        goto runtime_error;
    if (cafile) {
        error = gnutls_x509_trust_list_add_trust_file(
            roots, cafile, NULL, GNUTLS_X509_FMT_PEM, GNUTLS_TL_NO_DUPLICATES, 0);
        if (error < 0)
            goto runtime_error;
    }
    error = gnutls_x509_trust_list_verify_crt2(
        roots, certs, count, &purpose, 1, 0, status, NULL);
    if (error < 0)
        goto runtime_error;
    error = gnutls_x509_crt_get_key_usage(certs[0], &key_usage, NULL);
    if (error < 0 && error != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
        goto runtime_error;
    if (!error && !(key_usage & (GNUTLS_KEY_DIGITAL_SIGNATURE |
                                GNUTLS_KEY_KEY_ENCIPHERMENT |
                                GNUTLS_KEY_KEY_AGREEMENT)))
        *status |= GNUTLS_CERT_INVALID | GNUTLS_CERT_PURPOSE_MISMATCH;
    if (!gnutls_x509_crt_check_hostname(certs[0], normalized_host))
        *status |= GNUTLS_CERT_INVALID | GNUTLS_CERT_UNEXPECTED_OWNER;
    result = *status ? 1 : 0;
    message = !*status ? "Certificate chain is trusted" :
              (*status & GNUTLS_CERT_UNEXPECTED_OWNER) ? "Certificate hostname mismatch" :
              (*status & GNUTLS_CERT_EXPIRED) ? "Certificate has expired" :
              (*status & GNUTLS_CERT_NOT_ACTIVATED) ? "Certificate is not yet valid" :
              (*status & GNUTLS_CERT_PURPOSE_MISMATCH) ? "Certificate is not valid for TLS server authentication" :
              "Certificate chain is not trusted";
    goto out;
runtime_error:
    result = error == GNUTLS_E_MEMORY_ERROR ? -ENOMEM : -EIO;
    message = "Native certificate verification failed";
out:
    if (roots)
        gnutls_x509_trust_list_deinit(roots, 1);
    for (i = 0; i < count && i < 16; ++i)
        if (certs[i] && (!temporary || certs[i] != temporary->peer_cert))
            gnutls_x509_crt_deinit(certs[i]);
    if (temporary)
        openconnect_vpninfo_free(temporary);
    snprintf(reason, reason_size, "%s", message);
    return result;
}

void ocgui_set_peer_policy(struct openconnect_info *vpninfo,
                           ocgui_peer_policy_fn callback, void *context)
{
    vpninfo->ocgui_peer_policy = callback;
    vpninfo->ocgui_peer_policy_context = context;
}

#ifdef _WIN32
static int command_socket_error(void)
{
    switch (WSAGetLastError()) {
    case WSAEINTR: return EINTR;
    case WSAEWOULDBLOCK: return EAGAIN;
    case WSAENOTSOCK: return EBADF;
    case WSAEINVAL: return EINVAL;
    case WSAEACCES: return EACCES;
    case WSAEMFILE: return EMFILE;
    case WSAENOBUFS: return ENOMEM;
    case WSAECONNRESET: return ECONNRESET;
    case WSAECONNABORTED: return ECONNABORTED;
    case WSAENOTCONN: return ENOTCONN;
    case WSAESHUTDOWN: return EPIPE;
    default: return EIO;
    }
}
#endif

intptr_t ocgui_duplicate_cmd_handle(struct openconnect_info *vpninfo)
{
    if (!vpninfo || vpninfo->cmd_fd_write < 0) {
        errno = EBADF;
        return -1;
    }
#ifdef _WIN32
    WSAPROTOCOL_INFOW info;
    SOCKET copy;
    if (WSADuplicateSocketW((SOCKET)vpninfo->cmd_fd_write,
                           GetCurrentProcessId(), &info)) {
        errno = command_socket_error();
        return -1;
    }
    copy = WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO,
                      FROM_PROTOCOL_INFO, &info, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    if (copy == INVALID_SOCKET) {
        errno = command_socket_error();
        return -1;
    }
    return (intptr_t)copy;
#else
    int copy;
    do {
        copy = fcntl(vpninfo->cmd_fd_write, F_DUPFD_CLOEXEC, 0);
    } while (copy < 0 && errno == EINTR);
    return copy;
#endif
}

int ocgui_send_cmd(intptr_t handle, unsigned char command)
{
    if (handle == -1)
        return -EBADF;
#ifdef _WIN32
    int result, error;
    do {
        result = send((SOCKET)handle, (const char *)&command, 1, 0);
        error = result == SOCKET_ERROR ? command_socket_error() : 0;
    } while (error == EINTR);
    return error ? -error : result == 1 ? 0 : -EIO;
#else
    sigset_t blocked, previous, pending;
    int error, had_sigpipe;
    ssize_t result;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    error = pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    if (error)
        return -error;
    if (sigpending(&pending)) {
        error = errno;
        pthread_sigmask(SIG_SETMASK, &previous, NULL);
        return -error;
    }
    had_sigpipe = sigismember(&pending, SIGPIPE);
    do {
        result = write((int)handle, &command, 1);
    } while (result < 0 && errno == EINTR);
    error = result < 0 ? errno : result == 1 ? 0 : EIO;
    /* Do not consume a caller's pre-existing pending signal. With SIGPIPE
     * blocked, a newly generated pipe signal stays pending on this thread.
     * SIG_IGN can discard it, so check before the portable blocking sigwait. */
    if (error == EPIPE && !had_sigpipe && !sigpending(&pending) &&
        sigismember(&pending, SIGPIPE)) {
        int signal_number;
        sigwait(&blocked, &signal_number);
    }
    pthread_sigmask(SIG_SETMASK, &previous, NULL);
    return -error;
#endif
}

void ocgui_close_cmd_handle(intptr_t handle)
{
    int saved_errno = errno;
    if (handle != -1) {
#ifdef _WIN32
        closesocket((SOCKET)handle);
#else
        close((int)handle);
#endif
    }
    errno = saved_errno;
}

void ocgui_progress_bridge(void *privdata, int level, const char *format, ...)
{
    struct ocgui_progress_context *sink = privdata;
    char local[1024];
    char *message = local;
    va_list args, copy;
    int length;
    if (!sink || !sink->callback || !format)
        return;
    va_start(args, format);
    va_copy(copy, args);
    length = vsnprintf(local, sizeof(local), format, args);
    va_end(args);
    if (length < 0) {
        va_end(copy);
        sink->callback(sink->context, level, "Native progress formatting failed");
        return;
    }
    /* Upstream messages may include server data. Bound allocation, retaining
     * a valid UTF-8 prefix rather than allocating an attacker-chosen length. */
    if ((size_t)length >= sizeof(local)) {
        size_t capacity = (size_t)length < 65535 ? (size_t)length + 1 : 65536;
        message = malloc(capacity);
        if (!message) {
            va_end(copy);
            sink->callback(sink->context, level, "Native progress allocation failed");
            return;
        }
        vsnprintf(message, capacity, format, copy);
        if ((size_t)length >= capacity) {
            size_t end = capacity - 1;
            while (end && ((unsigned char)message[end - 1] & 0xc0) == 0x80)
                --end;
            if (end && (unsigned char)message[end - 1] >= 0xc0)
                --end;
            message[end] = '\0';
        }
    }
    va_end(copy);
    sink->callback(sink->context, level, message);
    if (message != local)
        free(message);
}

int ocgui_configure_tun(struct openconnect_info *vpninfo,
                        const char *script, const char *ifname)
{
    char *new_script, *new_ifname = NULL;
    if (!vpninfo || !script || !*script || (ifname && !*ifname))
        return -EINVAL;
    new_script = strdup(script);
    if (!new_script)
        return -ENOMEM;
    if (ifname) {
        new_ifname = strdup(ifname);
        if (!new_ifname) {
            free(new_script);
            return -ENOMEM;
        }
    }
    free(vpninfo->vpnc_script);
    free(vpninfo->ifname);
    vpninfo->vpnc_script = new_script;
    vpninfo->ifname = new_ifname;
    return 0;
}

int ocgui_set_script_env(struct openconnect_info *vpninfo, const char *name, const char *value)
{
    size_t i;
    if (!vpninfo || !name || !value ||
        (strcmp(name, "OCVPN_SERVICE_INSTANCE_ID") && strcmp(name, "OCVPN_ATTEMPT_ID")) ||
        strlen(value) != 36)
        return -EINVAL;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return -EINVAL;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) return -EINVAL;
    }
    return script_setenv(vpninfo, name, value, 0, 0);
}

int ocgui_tun_is_up(struct openconnect_info *vpninfo)
{
    return vpninfo && tun_is_up(vpninfo);
}

int ocgui_transport_is_udp(struct openconnect_info *vpninfo)
{
    return vpninfo && vpninfo->dtls_state == DTLS_CONNECTED;
}

int ocgui_getaddrinfo_numeric(const char *address, const char *service,
                              const struct addrinfo *hints, struct addrinfo **result)
{
    struct addrinfo numeric;
    if (!result)
        return EAI_FAIL;
    *result = NULL;
    if (!address || !*address)
        return EAI_NONAME;
    memset(&numeric, 0, sizeof(numeric));
    if (hints)
        numeric = *hints;
    numeric.ai_flags |= AI_NUMERICHOST;
    return getaddrinfo(address, service, &numeric, result);
}

int ocgui_getaddrinfo_system(const char *node, const char *service,
                             const struct addrinfo *hints, struct addrinfo **result)
{
    if (!result)
        return EAI_FAIL;
    *result = NULL;
    return getaddrinfo(node, service, hints, result);
}

void ocgui_freeaddrinfo(struct addrinfo *result)
{
    if (result)
        freeaddrinfo(result);
}
