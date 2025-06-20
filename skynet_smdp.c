/* Name: skynet_smdp.c
 * Description: Lightweight SM-DP+ server for eSIM profile delivery in srsRAN 4G
 * Purpose: Generates GSMA-compliant eSIM profiles for iPhone SE 5G
 * Date: June 21, 2025
 */

// gcc -o skynet_smdp skynet_smdp.c $(pkg-config --cflags --libs libmicrohttpd)

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <microhttpd.h>

/* Configuration constants */
#define SMDP_PORT 8080
#define MAX_IMSI_LEN 16
#define MAX_KI_LEN 33
#define MAX_OPC_LEN 33
#define MAX_PROFILE_LEN 256
#define MAX_ACTIVATION_CODE_LEN 128
#define MAX_RESPONSE_LEN 512
#define MAX_ERROR_MSG_LEN 256
#define MAX_CONFIG_LINES 10
#define MAX_LINE_LEN 256
#define MAX_FILENAME_LEN 128

/* Error codes */
typedef enum {
    SMDP_OK = 0,
    SMDP_ERR_INVALID_PARAM = -1,
    SMDP_ERR_FILE_OPEN = -2,
    SMDP_ERR_FILE_READ = -3,
    SMDP_ERR_INVALID_CONFIG = -4,
    SMDP_ERR_SERVER_START = -5,
    SMDP_ERR_PROFILE_GENERATE = -6
} smdp_error_t;

/* eSIM profile structure */
typedef struct {
    char imsi[MAX_IMSI_LEN];
    char ki[MAX_KI_LEN];
    char opc[MAX_OPC_LEN];
    char iccid[20]; /* 19-digit ICCID + Luhn check digit */
} esim_profile_t;

/* Server state */
typedef struct {
    FILE *log_file; /* stderr if NULL */
    esim_profile_t profiles[MAX_CONFIG_LINES];
    uint32_t profile_count;
} smdp_state_t;

/* Function declarations */
static smdp_error_t load_config(const char *filename, smdp_state_t *state);
static smdp_error_t generate_profile(const smdp_state_t *state, uint32_t index, char *profile, uint32_t max_len);
static smdp_error_t generate_activation_code(const esim_profile_t *profile, char *code, uint32_t max_len);
static void log_error(const smdp_state_t *state, const char *msg);
static enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     const char *version, const char *upload_data,
                                     size_t *upload_data_size, void **con_cls);

/* Global state */
static smdp_state_t global_state = { .log_file = NULL, .profile_count = 0 };

/* Load configuration file (same format as skynet_sim.c) */
static smdp_error_t load_config(const char *filename, smdp_state_t *state) {
    FILE *fp = NULL;
    char line[MAX_LINE_LEN] = {0};
    char key[32] = {0};
    char value[MAX_LINE_LEN] = {0};
    uint32_t current_profile = 0;

    if (filename == NULL || state == NULL) {
        return SMDP_ERR_INVALID_PARAM;
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return SMDP_ERR_FILE_OPEN;
    }

    state->profile_count = 0;
    while (fgets(line, MAX_LINE_LEN, fp) != NULL && current_profile < MAX_CONFIG_LINES) {
        if (line[0] == '\0' || line[0] == '#' || line[0] == '\n') {
            continue;
        }

        if (sscanf(line, "%31[^=]=%255[^\n]", key, value) != 2) {
            fclose(fp);
            return SMDP_ERR_INVALID_CONFIG;
        }

        while (value[0] == ' ') {
            memmove(value, value + 1, strlen(value));
        }
        size_t len = strlen(value);
        while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\n')) {
            value[len - 1] = '\0';
            len--;
        }

        esim_profile_t *profile = &state->profiles[current_profile];
        if (strcmp(key, "imsi") == 0 && len < MAX_IMSI_LEN) {
            strncpy(profile->imsi, value, MAX_IMSI_LEN - 1);
            profile->imsi[MAX_IMSI_LEN - 1] = '\0';
        } else if (strcmp(key, "ki") == 0 && len < MAX_KI_LEN) {
            strncpy(profile->ki, value, MAX_KI_LEN - 1);
            profile->ki[MAX_KI_LEN - 1] = '\0';
        } else if (strcmp(key, "opc") == 0 && len < MAX_OPC_LEN) {
            strncpy(profile->opc, value, MAX_OPC_LEN - 1);
            profile->opc[MAX_OPC_LEN - 1] = '\0';
        } else if (strcmp(key, "iccid") == 0 && len < 20) {
            strncpy(profile->iccid, value, 19);
            profile->iccid[19] = '\0';
        } else {
            continue;
        }

        if (profile->imsi[0] != '\0' && profile->ki[0] != '\0' && profile->opc[0] != '\0' && profile->iccid[0] != '\0') {
            current_profile++;
            state->profile_count = current_profile;
            profile = &state->profiles[current_profile];
            profile->imsi[0] = '\0';
            profile->ki[0] = '\0';
            profile->opc[0] = '\0';
            profile->iccid[0] = '\0';
        }
    }

    fclose(fp);
    if (state->profile_count == 0) {
        return SMDP_ERR_INVALID_CONFIG;
    }
    return SMDP_OK;
}

/* Generate eSIM profile (simplified JSON-like format) */
static smdp_error_t generate_profile(const smdp_state_t *state, uint32_t index, char *profile, uint32_t max_len) {
    if (state == NULL || profile == NULL || index >= state->profile_count || max_len < MAX_PROFILE_LEN) {
        return SMDP_ERR_INVALID_PARAM;
    }

    const esim_profile_t *p = &state->profiles[index];
    int written = snprintf(profile, max_len,
                           "{\"imsi\":\"%s\",\"ki\":\"%s\",\"opc\":\"%s\",\"iccid\":\"%s\"}",
                           p->imsi, p->ki, p->opc, p->iccid);
    if (written < 0 || (uint32_t)written >= max_len) {
        return SMDP_ERR_PROFILE_GENERATE;
    }
    return SMDP_OK;
}

/* Generate activation code for QR code */
static smdp_error_t generate_activation_code(const esim_profile_t *profile, char *code, uint32_t max_len) {
    if (profile == NULL || code == NULL || max_len < MAX_ACTIVATION_CODE_LEN) {
        return SMDP_ERR_INVALID_PARAM;
    }

    int written = snprintf(code, max_len, "%s:%s:%s:%s",
                           profile->imsi, profile->ki, profile->opc, profile->iccid);
    if (written < 0 || (uint32_t)written >= max_len) {
        return SMDP_ERR_PROFILE_GENERATE;
    }
    return SMDP_OK;
}

/* Log error message */
static void log_error(const smdp_state_t *state, const char *msg) {
    FILE *out = (state->log_file != NULL) ? state->log_file : stderr;
    fprintf(out, "SMDP ERROR: %s\n", msg);
    fflush(out);
}

/* HTTP request handler */
static enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
                                     const char *url, const char *method,
                                     const char *version, const char *upload_data,
                                     size_t *upload_data_size, void **con_cls) {
    smdp_state_t *state = (smdp_state_t *)cls;
    char response[MAX_RESPONSE_LEN] = {0};
    char error_msg[MAX_ERROR_MSG_LEN] = {0};
    struct MHD_Response *mhd_response = NULL;
    enum MHD_Result ret = MHD_NO;
    smdp_error_t err;
    int http_status = MHD_HTTP_OK;

    if (strcmp(method, "GET") != 0) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Unsupported method: %s", method);
        log_error(state, error_msg);
        snprintf(response, MAX_RESPONSE_LEN, "{\"error\":\"%s\"}", error_msg);
        http_status = MHD_HTTP_METHOD_NOT_ALLOWED;
        goto send_response;
    }

    if (strncmp(url, "/profile/", 9) != 0) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Invalid URL: %s", url);
        log_error(state, error_msg);
        snprintf(response, MAX_RESPONSE_LEN, "{\"error\":\"%s\"}", error_msg);
        http_status = MHD_HTTP_NOT_FOUND;
        goto send_response;
    }

    uint32_t index = 0;
    if (sscanf(url + 9, "%u", &index) != 1 || index >= state->profile_count) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Invalid profile index: %s", url + 9);
        log_error(state, error_msg);
        snprintf(response, MAX_RESPONSE_LEN, "{\"error\":\"%s\"}", error_msg);
        http_status = MHD_HTTP_NOT_FOUND;
        goto send_response;
    }

    err = generate_profile(state, index, response, MAX_RESPONSE_LEN);
    if (err != SMDP_OK) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Failed to generate profile: %d", err);
        log_error(state, error_msg);
        snprintf(response, MAX_RESPONSE_LEN, "{\"error\":\"%s\"}", error_msg);
        http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        goto send_response;
    }

send_response:
    mhd_response = MHD_create_response_from_buffer(strlen(response), response, MHD_RESPMEM_MUST_COPY);
    if (mhd_response == NULL) {
        log_error(state, "Failed to create HTTP response");
        return MHD_NO;
    }

    ret = MHD_queue_response(connection, http_status, mhd_response);
    MHD_destroy_response(mhd_response);
    return ret;
}

/* Main function */
int main(int argc, char *argv[]) {
    char error_msg[MAX_ERROR_MSG_LEN] = {0};
    smdp_error_t ret = SMDP_OK;
    struct MHD_Daemon *daemon = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    ret = load_config(argv[1], &global_state);
    if (ret != SMDP_OK) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Failed to load config: %d", ret);
        log_error(&global_state, error_msg);
        return 1;
    }

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, SMDP_PORT, NULL, NULL,
                              &handle_request, &global_state, MHD_OPTION_END);
    if (daemon == NULL) {
        log_error(&global_state, "Failed to start HTTP server");
        return 1;
    }

    printf("SMDP+ server running on http://localhost:%d\n", SMDP_PORT);
    printf("Press Enter to stop...\n");
    getchar();

    MHD_stop_daemon(daemon);
    return 0;
}
