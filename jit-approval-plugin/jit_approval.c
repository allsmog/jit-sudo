/*
 * jit_approval.c - JIT Sudo Approval Plugin (Simplified Version)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sudo_plugin.h>

#define PLUGIN_NAME "jit_approval"
#define JIT_SOCKET_PATH "/run/jit-sudo/jitd.sock"
#define MAX_RESPONSE_SIZE 4096

/* Plugin state */
struct jit_approval_state {
    char *socket_path;
    int timeout_ms;
} plugin_state = { .socket_path = JIT_SOCKET_PATH, .timeout_ms = 2000 };

/* Forward declarations */
static int jit_approval_open(unsigned int version, sudo_conv_t conversation,
                             sudo_printf_t sudo_plugin_printf, char * const settings[],
                             char * const user_info[], int submit_optind,
                             char * const submit_argv[], char * const submit_envp[],
                             char * const plugin_options[], const char **errstr);

static void jit_approval_close(void);

static int jit_approval_check(char * const command_info[], char * const run_argv[],
                              char * const run_envp[], const char **errstr);

static int jit_approval_show_version(int verbose);

/*
 * Simple check implementation - just deny for now with helpful message
 */
static int jit_approval_check(char * const command_info[], char * const run_argv[],
                              char * const run_envp[], const char **errstr) {
    (void)command_info;
    (void)run_argv;
    (void)run_envp;
    
    *errstr = "JIT approval required (no active grant).\n"
              "→ Run: jitctl request --cmd \"<command>\" --ttl 15m\n"
              "  or visit: https://jit-broker.example.com/requests/new";
    
    return 0; // Deny for now
}

/*
 * Plugin open - initialize state
 */
static int jit_approval_open(unsigned int version, sudo_conv_t conversation,
                             sudo_printf_t sudo_plugin_printf, char * const settings[],
                             char * const user_info[], int submit_optind,
                             char * const submit_argv[], char * const submit_envp[],
                             char * const plugin_options[], const char **errstr) {
    
    (void)conversation;
    (void)sudo_plugin_printf;
    (void)settings;
    (void)user_info;
    (void)submit_optind;
    (void)submit_argv;
    (void)submit_envp;
    (void)plugin_options;
    
    if (version != SUDO_API_VERSION) {
        *errstr = "Incompatible plugin API version";
        return -1;
    }
    
    return 1; // Success
}

/*
 * Plugin close - cleanup
 */
static void jit_approval_close(void) {
    // Nothing to cleanup in simple version
}

/*
 * Show plugin version
 */
static int jit_approval_show_version(int verbose) {
    printf("JIT Sudo Approval Plugin version 1.0.0\n");
    if (verbose) {
        printf("Sudo plugin API version: %u\n", SUDO_API_VERSION);
        printf("Default socket: %s\n", JIT_SOCKET_PATH);
    }
    return 1;
}

/*
 * Plugin entry point - sudo looks for this symbol
 */
struct approval_plugin jit_approval = {
    SUDO_APPROVAL_PLUGIN,
    SUDO_API_VERSION,
    jit_approval_open,
    jit_approval_close,
    jit_approval_check,
    jit_approval_show_version,
};
