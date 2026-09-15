/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 OpenConnect GUI contributors
 */
#ifndef OCGUI_BRIDGE_H
#define OCGUI_BRIDGE_H
#ifdef _WIN32
#include <winsock2.h>
#endif
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#define OC_GUI_EAGAIN (-EAGAIN)
#include "openconnect.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ABI 4. Place this at the beginning of the constructor's privdata object.
 * The owner must retain it until openconnect_vpninfo_free() returns. All
 * callbacks run synchronously on the native context's owning thread. Rust
 * callbacks must catch panics; no exception may unwind across this boundary.
 * Message bytes are UTF-8, borrowed only for the callback, and NOT redacted.
 * Never send raw progress messages to a persistent log or frontend.
 */
typedef void (*ocgui_progress_fn)(void *context, int level, const char *utf8_message);
struct ocgui_progress_context {
    void *context;
    ocgui_progress_fn callback;
};
void ocgui_progress_bridge(void *privdata, int level, const char *format, ...);
unsigned int ocgui_bridge_abi(void);
unsigned int ocgui_api_version_major(void);
unsigned int ocgui_api_version_minor(void);
int ocgui_has_hpke(void);

/* GP owner-thread only. Configure before obtain_cookie: mode 0 embedded,
 * 1 external; returns 0 or -EINVAL. The preferred mode survives a portal's
 * embedded fallback so gateway prelogin negotiates independently.
 * allowed: 1 explicit yes, 0 explicit no, -1 absent/unknown.
 * phase: 1 portal, 2 gateway, 0 outside authentication.
 * retry: 0 requests one embedded prelogin retry for this phase, -EPERM if
 * not in its first prelogin form with explicit no/requested external, or
 * -EALREADY if already requested/used. Caller MUST immediately return
 * -EAGAIN from its current form/webview callback. No credential retry.
 */
int ocgui_set_gp_browser_mode(struct openconnect_info *vpninfo, int mode);
int ocgui_gp_external_allowed(struct openconnect_info *vpninfo);
int ocgui_gp_auth_phase(struct openconnect_info *vpninfo);
int ocgui_gp_retry_embedded(struct openconnect_info *vpninfo);

/* Offline, synchronous verification after openconnect_init_ssl().
 * chain is leaf-first, 1..16 borrowed DER certs, <=1 MiB in total; neither
 * descriptors nor bytes are freed, changed, retained, or logged. All input
 * strings are borrowed NUL-terminated strings (host <=253, CA path <=4096,
 * pin <=128 bytes). host is DNS or unbracketed/bracketed numeric IP, no port.
 * NULL pin uses system trust plus optional PEM cafile, chain/time/hostname/
 * TLS-server key-purpose checks. Non-NULL pin uses ONLY the complete native
 * hash supplied by caller (no CA/system alternative); host scoping is the
 * caller's responsibility. No network/AIA/OCSP requests are made.
 * Returns 0 trusted/pin match, 1 untrusted/mismatch, negative errno on
 * invalid input/runtime failure. fingerprint requires >=56 bytes and gets
 * the complete native pin-sha256 hash once the leaf is parsed and hashed,
 * even if subsequent verification fails. reason requires >=1 byte and
 * contains only bounded nonsecret text. Both outputs are NUL terminated.
 * status is required: GnuTLS certificate-status bits (0 for pin match,
 * GNUTLS_CERT_INVALID for mismatch or an incomplete verification).
 * All temporary contexts, imported certificates and roots are native-owned
 * and destroyed before return; caller retains every supplied buffer.
 */
int ocgui_verify_browser_chain(const struct oc_cert *chain, unsigned count,
                               const char *host, const char *cafile,
                               const char *pin, char *fingerprint,
                               size_t fingerprint_size, char *reason,
                               size_t reason_size, unsigned *status);

/* Owner-thread only. NULL disables the policy and restores upstream behavior.
 * The policy replaces the failure-only validator and runs after native trust
 * and hostname checks, including successful checks (reason == NULL). Return
 * zero to accept, nonzero to reject. Chain/details/hash APIs are available
 * synchronously; all borrowed data expires on callback return. Free copied
 * native certificate data with the matching OpenConnect API, never Rust free.
 * Context is borrowed until replacement or vpninfo destruction. Never unwind.
 */
typedef int (*ocgui_peer_policy_fn)(void *context, const char *reason);
void ocgui_set_peer_policy(struct openconnect_info *vpninfo,
                           ocgui_peer_policy_fn callback, void *context);

/* Duplicate on the owner thread AFTER successful setup_cmd_pipe, before
 * publishing to other threads. Returns an independently owned non-inheritable
 * handle, or -1 and errno. No native-context access is needed to send/close.
 * Context destruction may race send safely (EPIPE/connection error); duplicate
 * itself MUST NOT race destruction. Serialize close with all send calls and
 * close exactly once; never use the original OpenConnect-owned write handle.
 * send returns 0 or negative errno; EINTR is retried, EAGAIN is not success.
 * Unix sends suppress only SIGPIPE generated on the calling thread. Windows
 * uses SOCKET duplication/send/closesocket, with WSA errors mapped to errno.
 * close preserves errno; it must never be retried (descriptor reuse).
 */
intptr_t ocgui_duplicate_cmd_handle(struct openconnect_info *vpninfo);
int ocgui_send_cmd(intptr_t handle, unsigned char command);
void ocgui_close_cmd_handle(intptr_t handle);

/* Configure only; mainloop creates the TUN after protocol negotiation.
 * Caller supplies the fixed trusted installed helper, never a frontend path.
 * Both strings are copied and eventually freed by the same native runtime.
 */
int ocgui_configure_tun(struct openconnect_info *vpninfo,
                        const char *script, const char *ifname);
/* Owner-thread only. Environment is copied with the native allocator.
 * Only fixed nonsecret OCVPN transaction identifiers are accepted. */
int ocgui_set_script_env(struct openconnect_info *, const char *, const char *);
int ocgui_tun_is_up(struct openconnect_info *);
/* Includes native ESP transports, not only TLS cipher sessions. */
int ocgui_transport_is_udp(struct openconnect_info *);

/* Use inside the Rust getaddrinfo override after an exact host match.
 * address must be an unbracketed numeric IPv4/IPv6 literal. Do not override
 * unmatched hosts (including proxy hosts): use ocgui_getaddrinfo_system.
 * Results come from the native getaddrinfo allocator. On successful return,
 * transfer the list to OpenConnect, which calls native freeaddrinfo itself.
 * On local cancellation/error before transfer use ocgui_freeaddrinfo.
 */
int ocgui_getaddrinfo_numeric(const char *address, const char *service,
                              const struct addrinfo *hints, struct addrinfo **result);
int ocgui_getaddrinfo_system(const char *node, const char *service,
                             const struct addrinfo *hints, struct addrinfo **result);
void ocgui_freeaddrinfo(struct addrinfo *result);
#ifdef __cplusplus
}
#endif
#endif
