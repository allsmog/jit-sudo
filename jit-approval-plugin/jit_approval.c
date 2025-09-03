#include <stdarg.h>
/*
 * jit_approval.c - JIT Sudo Approval Plugin with jitd Communication
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sudo_plugin.h>

#define PLUGIN_NAME "jit_approval"
#define JIT_SOCKET_PATH "/run/jit-sudo/jitd.sock"
#define MAX_RESPONSE_SIZE 4096

/* Plugin state */
struct jit_approval_state {
    char *socket_path;
    int timeout_ms;
    FILE *debug_file;
} plugin_state = { 
    .socket_path = JIT_SOCKET_PATH, 
    .timeout_ms = 2000,
    .debug_file = NULL
};

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

/* Logging helper */
static void debug_log(const char *fmt, ...) {
    if (!plugin_state.debug_file) {
        plugin_state.debug_file = fopen("/tmp/jit_approval.log", "a");
        if (!plugin_state.debug_file) return;
    }
    
    va_list args;
    va_start(args, fmt);
    time_t now = time(NULL);
    fprintf(plugin_state.debug_file, "[%ld] ", now);
    vfprintf(plugin_state.debug_file, fmt, args);
    fprintf(plugin_state.debug_file, "\n");
    fflush(plugin_state.debug_file);
    va_end(args);
}

/*
 * Build execution context JSON for jitd
 */
static char* build_exec_context(char * const command_info[], 
                                char * const run_argv[]) {
    const char *user = "unknown";
    const char *runas = "root";
    const char *command = run_argv ? run_argv[0] : "unknown";
    
    // Parse command_info for actual values
    for (int i = 0; command_info && command_info[i]; i++) {
        if (strncmp(command_info[i], "user=", 5) == 0) {
            user = command_info[i] + 5;
        } else if (strncmp(command_info[i], "runas_user=", 11) == 0) {
            runas = command_info[i] + 11;
        }
    }
    
    // Build argv array
    char argv_str[1024] = "";
    if (run_argv) {
        for (int i = 0; run_argv[i] && i < 10; i++) {
            if (i > 0) strcat(argv_str, " ");
            strncat(argv_str, run_argv[i], 1023 - strlen(argv_str));
        }
    }
    
    // Build JSON request for jitd
    char *context = malloc(2048);
    if (!context) return NULL;
    
    snprintf(context, 2048,
        "{"
        "\"ValidateExecution\":{"
        "\"context\":{"
        "\"user\":\"%s\","
        "\"runas\":\"%s\","
        "\"command\":\"%s\","
        "\"argv\":[\"%s\"],"
        "\"cwd\":\"/\","
        "\"env\":{},"
        "\"host_id\":\"localhost\","
        "\"timestamp\":%ld"
        "}"
        "}"
        "}",
        user, runas, command, argv_str, time(NULL)
    );
    
    debug_log("Built context: %s", context);
    return context;
}

/*
 * Query jitd for grant validation
 */
static int query_jitd(const char *request, char *response, size_t resp_size) {
    int sock = -1;
    struct sockaddr_un addr;
    int ret = -1;
    
    debug_log("Querying jitd with: %s", request);
    
    // Create socket
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        debug_log("Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    // Connect to jitd
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, plugin_state.socket_path, sizeof(addr.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        debug_log("Failed to connect to jitd: %s", strerror(errno));
        goto cleanup;
    }
    
    // Send request
    size_t req_len = strlen(request);
    if (write(sock, request, req_len) != (ssize_t)req_len) {
        debug_log("Failed to send request to jitd");
        goto cleanup;
    }
    
    debug_log("Sent request, waiting for response...");
    
    // Read response
    ssize_t n = read(sock, response, resp_size - 1);
    if (n > 0) {
        response[n] = 0;
        debug_log("Received response: %s", response);
        ret = 0;
    } else {
        debug_log("Failed to read response from jitd: %s", strerror(errno));
    }
    
cleanup:
    if (sock >= 0) close(sock);
    return ret;
}

/*
 * Check if command is approved
 */
static int jit_approval_check(char * const command_info[], char * const run_argv[],
                              char * const run_envp[], const char **errstr) {
    
    (void)run_envp; // Unused parameter
    
    debug_log("=== JIT Approval Check Starting ===");
    
    // Build execution context
    char *context = build_exec_context(command_info, run_argv);
    if (!context) {
        *errstr = "Failed to build execution context";
        debug_log("Failed to build execution context");
        return 0; // Deny
    }
    
    // Query jitd
    char response[MAX_RESPONSE_SIZE];
    if (query_jitd(context, response, sizeof(response)) < 0) {
        *errstr = "JIT approval required (no active grant).\n"
                  "→ Run: jitctl request --cmd \"<command>\" --ttl 15m\n"
                  "  or visit: https://jit-broker.example.com/requests/new";
        free(context);
        debug_log("Failed to communicate with jitd");
        return 0; // Deny
    }
    
    debug_log("jitd response: %s", response);
    
    // Parse response - look for "allowed":true
    int approved = 0;
    if (strstr(response, "\"allowed\":true") != NULL) {
        approved = 1;
        debug_log("=== COMMAND APPROVED by JIT ===");
    } else {
        debug_log("=== COMMAND DENIED by JIT ===");
        *errstr = "JIT approval required (no matching grant found).\n"
                  "→ Run: jitctl request --cmd \"<command>\" --ttl 15m\n"
                  "  or visit: https://jit-broker.example.com/requests/new";
    }
    
    free(context);
    return approved;
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
    
    debug_log("=== JIT Approval Plugin Initialized ===");
    debug_log("Socket: %s", plugin_state.socket_path);
    
    return 1; // Success
}

/*
 * Plugin close - cleanup
 */
static void jit_approval_close(void) {
    debug_log("=== JIT Approval Plugin Closing ===");
    if (plugin_state.debug_file) {
        fclose(plugin_state.debug_file);
        plugin_state.debug_file = NULL;
    }
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
