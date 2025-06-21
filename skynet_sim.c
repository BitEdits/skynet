// gcc -o skynet_sim skynet_sim.c $(pkg-config --cflags --libs libpcsclite libusb-1.0 libqrencode libpng)

/* Name: skynet_sim.c
 * Description: Utility to flash SIM cards for srsRAN setups with PC/SC and CCID support.
 * Dependencies: libpcsclite, libusb-1.0.
 * Support: PCSC (OMNIKEY, ACR38U), CCID devices (Автор).
 * Date: June 21, 2025.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <qrencode.h>
#include <png.h>

#ifdef _WIN32
#include <winscard.h>
#else
#include <pcsclite.h>
#include <winscard.h>
#endif

#include <libusb-1.0/libusb.h>

/* Configuration constants */
#define MAX_IMSI_LEN 16
#define MAX_KI_LEN 33
#define MAX_OPC_LEN 33
#define MAX_MCC_LEN 4
#define MAX_MNC_LEN 3
#define MAX_LINE_LEN 256
#define MAX_FILENAME_LEN 128
#define MAX_ERROR_MSG_LEN 256
#define MAX_READER_NAME_LEN 128
#define MAX_APDU_LEN 256
#define MAX_PROGRAMMERS 5
#define CCID_TIMEOUT_MS 1000
#define MAX_QR_PAYLOAD_LEN 512
#define MAX_ACTIVATION_CODE_LEN 128
#define QR_SCALE_FACTOR 4

/* Error codes */
typedef enum {
    SIM_OK = 0,
    SIM_ERR_INVALID_PARAM = -1,
    SIM_ERR_FILE_OPEN = -2,
    SIM_ERR_FILE_READ = -3,
    SIM_ERR_INVALID_CONFIG = -4,
    SIM_ERR_PROGRAMMER_NOT_FOUND = -5,
    SIM_ERR_PCSC_CONTEXT = -6,
    SIM_ERR_PCSC_CONNECT = -7,
    SIM_ERR_PCSC_TRANSMIT = -8,
    SIM_ERR_PCSC_DISCONNECT = -9,
    SIM_ERR_CCID_INIT = -10,
    SIM_ERR_CCID_TRANSMIT = -11,
    SIM_ERR_CCID_CLOSE = -12,
    SIM_ERR_QR_GENERATE = -13,
    SIM_ERR_INVALID_ESIM_PROFILE = -14,
    SIM_ERR_PNG_WRITE = -15
} sim_error_t;

/* SIM card parameters */
typedef struct {
    char imsi[MAX_IMSI_LEN];
    char ki[MAX_KI_LEN];
    char opc[MAX_OPC_LEN];
    char mcc[MAX_MCC_LEN];
    char mnc[MAX_MNC_LEN];
} sim_params_t;

/* Programmer driver interface */
typedef struct {
    const char *name;
    sim_error_t (*init)(void *state);
    sim_error_t (*write)(void *state, const sim_params_t *params);
    sim_error_t (*close)(void *state);
} programmer_driver_t;

/* PC/SC programmer state */
typedef struct {
    SCARDCONTEXT context;
    SCARDHANDLE card;
    char reader_name[MAX_READER_NAME_LEN];
} pcsc_programmer_t;

/* CCID programmer state */
typedef struct {
    libusb_context *context;
    libusb_device_handle *handle;
} ccid_programmer_t;

/* Global state */
typedef struct {
    FILE *log_file;
    const programmer_driver_t *driver;
    union {
        pcsc_programmer_t pcsc;
        ccid_programmer_t ccid;
    } state;
    int esim_mode;
    int srsran_mode;
    char qr_output_file[MAX_FILENAME_LEN];
} sim_state_t;

/* Function declarations */
static sim_error_t parse_config(const char *filename, sim_params_t *params);
static sim_error_t pcsc_init(void *state);
static sim_error_t pcsc_write(void *state, const sim_params_t *params);
static sim_error_t pcsc_close(void *state);
static sim_error_t ccid_init(void *state);
static sim_error_t ccid_write(void *state, const sim_params_t *params);
static sim_error_t ccid_close(void *state);
static sim_error_t generate_esim_qr(const sim_state_t *state, const sim_params_t *params);
static sim_error_t select_programmer(const char *name, sim_state_t *state);
static void log_error(const sim_state_t *state, const char *msg);
static sim_error_t hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len);

/* Programmer driver table */
static const programmer_driver_t programmers[MAX_PROGRAMMERS] = {
    { "OMNIKEY", pcsc_init, pcsc_write, pcsc_close },
    { "ACR38U", pcsc_init, pcsc_write, pcsc_close },
    { "GenericPCSC", pcsc_init, pcsc_write, pcsc_close },
    { "CCID_Generic", ccid_init, ccid_write, ccid_close },
    { NULL, NULL, NULL, NULL }
};

/* Convert hex string to bytes */
static sim_error_t hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > max_len) {
        return SIM_ERR_INVALID_PARAM;
    }
    for (size_t i = 0; i < len / 2; i++) {
        char buf[3] = {hex[2 * i], hex[2 * i + 1], '\0'};
        char *endptr = NULL;
        long val = strtol(buf, &endptr, 16);
        if (*endptr != '\0' || val < 0 || val > 255) {
            return SIM_ERR_INVALID_PARAM;
        }
        bytes[i] = (uint8_t)val;
    }
    return SIM_OK;
}

/* Generate eSIM QR code */
static sim_error_t generate_esim_qr(const sim_state_t *state, const sim_params_t *params) {
    char qr_payload[MAX_QR_PAYLOAD_LEN] = {0};
    char activation_code[MAX_ACTIVATION_CODE_LEN] = {0};

    if (state == NULL || params == NULL || state->qr_output_file[0] == '\0') {
        return SIM_ERR_INVALID_PARAM;
    }

    snprintf(activation_code, MAX_ACTIVATION_CODE_LEN, "%s:%s:%s", params->imsi, params->ki, params->opc);
    snprintf(qr_payload, MAX_QR_PAYLOAD_LEN, "LPA:1$localhost$%s", activation_code);
    if (strlen(qr_payload) >= MAX_QR_PAYLOAD_LEN) {
        return SIM_ERR_INVALID_ESIM_PROFILE;
    }

    QRcode *qrcode = QRcode_encodeString(qr_payload, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (qrcode == NULL) {
        return SIM_ERR_QR_GENERATE;
    }

    FILE *fp = fopen(state->qr_output_file, "wb");
    if (fp == NULL) {
        QRcode_free(qrcode);
        return SIM_ERR_FILE_OPEN;
    }

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (png == NULL) {
        fclose(fp);
        QRcode_free(qrcode);
        return SIM_ERR_PNG_WRITE;
    }

    png_infop info = png_create_info_struct(png);
    if (info == NULL) {
        png_destroy_write_struct(&png, NULL);
        fclose(fp);
        QRcode_free(qrcode);
        return SIM_ERR_PNG_WRITE;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        QRcode_free(qrcode);
        return SIM_ERR_PNG_WRITE;
    }

    png_init_io(png, fp);
    int width = qrcode->width * QR_SCALE_FACTOR;
    png_set_IHDR(png, info, width, width, 1, PNG_COLOR_TYPE_GRAY, PNG_INTERLACE_NONE,
                 PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);
    png_write_info(png, info);

    uint8_t *row = (uint8_t *)calloc(width, 1);
    if (row == NULL) {
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        QRcode_free(qrcode);
        return SIM_ERR_PNG_WRITE;
    }

    for (int y = 0; y < width; y++) {
        for (int x = 0; x < width; x++) {
            int qr_x = x / QR_SCALE_FACTOR;
            int qr_y = y / QR_SCALE_FACTOR;
            row[x] = (qrcode->data[qr_y * qrcode->width + qr_x] & 1) ? 0 : 255;
        }
        png_write_row(png, row);
    }

    free(row);
    png_write_end(png, NULL);
    png_destroy_write_struct(&png, &info);
    fclose(fp);
    QRcode_free(qrcode);
    return SIM_OK;
}

/* PC/SC: Initialize programmer */
static sim_error_t pcsc_init(void *state) {
    pcsc_programmer_t *pcsc = (pcsc_programmer_t *)state;
    LONG rv = SCARD_S_SUCCESS;

    rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &pcsc->context);
    if (rv != SCARD_S_SUCCESS) {
        return SIM_ERR_PCSC_CONTEXT;
    }

    DWORD reader_len = MAX_READER_NAME_LEN;
    rv = SCardListReaders(pcsc->context, NULL, pcsc->reader_name, &reader_len);
    if (rv != SCARD_S_SUCCESS || pcsc->reader_name[0] == '\0') {
        SCardReleaseContext(pcsc->context);
        return SIM_ERR_PCSC_CONNECT;
    }

    DWORD active_protocol = 0;
    rv = SCardConnect(pcsc->context, pcsc->reader_name, SCARD_SHARE_SHARED,
                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &pcsc->card, &active_protocol);
    if (rv != SCARD_S_SUCCESS) {
        SCardReleaseContext(pcsc->context);
        return SIM_ERR_PCSC_CONNECT;
    }

    return SIM_OK;
}

/* PC/SC: Write SIM parameters */
static sim_error_t pcsc_write(void *state, const sim_params_t *params) {
    pcsc_programmer_t *pcsc = (pcsc_programmer_t *)state;
    if (params == NULL || pcsc == NULL) {
        return SIM_ERR_INVALID_PARAM;
    }

    LONG rv = SCARD_S_SUCCESS;
    uint8_t apdu[MAX_APDU_LEN] = {0};
    uint8_t response[MAX_APDU_LEN] = {0};
    DWORD response_len = MAX_APDU_LEN;
    size_t apdu_len = 0;

    uint8_t select_usim[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00};
    apdu_len = sizeof(select_usim);
    memcpy(apdu, select_usim, apdu_len);
    rv = SCardTransmit(pcsc->card, SCARD_PCI_T1, apdu, apdu_len, NULL, response, &response_len);
    if (rv != SCARD_S_SUCCESS || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
        return SIM_ERR_PCSC_TRANSMIT;
    }

    uint8_t imsi_bytes[9] = {0};
    if (strlen(params->imsi) != 15) {
        return SIM_ERR_INVALID_PARAM;
    }
    imsi_bytes[0] = 0x08;
    for (size_t i = 0; i < 8; i++) {
        char digit1 = params->imsi[2 * i];
        char digit2 = params->imsi[2 * i + 1];
        imsi_bytes[i + 1] = ((digit1 - '0') << 4) | (digit2 - '0');
    }
    uint8_t write_imsi[] = {0x00, 0xA4, 0x04, 0x00, 0x02, 0x6F, 0x07,
                            0x00, 0xDC, 0x01, 0x04, 0x09};
    memcpy(apdu, write_imsi, sizeof(write_imsi));
    memcpy(apdu + sizeof(write_imsi), imsi_bytes, 9);
    apdu_len = sizeof(write_imsi) + 9;
    response_len = MAX_APDU_LEN;
    rv = SCardTransmit(pcsc->card, SCARD_PCI_T1, apdu, apdu_len, NULL, response, &response_len);
    if (rv != SCARD_S_SUCCESS || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
        return SIM_ERR_PCSC_TRANSMIT;
    }

    uint8_t ki_bytes[16] = {0};
    if (hex_to_bytes(params->ki, ki_bytes, 16) != SIM_OK) {
        return SIM_ERR_INVALID_PARAM;
    }
    uint8_t write_ki[] = {0x00, 0xDC, 0x01, 0x04, 0x10};
    memcpy(apdu, write_ki, sizeof(write_ki));
    memcpy(apdu + sizeof(write_ki), ki_bytes, 16);
    apdu_len = sizeof(write_ki) + 16;
    response_len = MAX_APDU_LEN;
    rv = SCardTransmit(pcsc->card, SCARD_PCI_T1, apdu, apdu_len, NULL, response, &response_len);
    if (rv != SCARD_S_SUCCESS || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
        return SIM_ERR_PCSC_TRANSMIT;
    }

    uint8_t opc_bytes[16] = {0};
    if (hex_to_bytes(params->opc, opc_bytes, 16) != SIM_OK) {
        return SIM_ERR_INVALID_PARAM;
    }
    memcpy(apdu, write_ki, sizeof(write_ki));
    memcpy(apdu + sizeof(write_ki), opc_bytes, 16);
    apdu_len = sizeof(write_ki) + 16;
    response_len = MAX_APDU_LEN;
    rv = SCardTransmit(pcsc->card, SCARD_PCI_T1, apdu, apdu_len, NULL, response, &response_len);
    if (rv != SCARD_S_SUCCESS || response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
        return SIM_ERR_PCSC_TRANSMIT;
    }

    return SIM_OK;
}

/* PC/SC: Close programmer */
static sim_error_t pcsc_close(void *state) {
    pcsc_programmer_t *pcsc = (pcsc_programmer_t *)state;
    LONG rv = SCARD_S_SUCCESS;

    if (pcsc->card != 0) {
        rv = SCardDisconnect(pcsc->card, SCARD_LEAVE_CARD);
        if (rv != SCARD_S_SUCCESS) {
            return SIM_ERR_PCSC_DISCONNECT;
        }
        pcsc->card = 0;
    }
    if (pcsc->context != 0) {
        rv = SCardReleaseContext(pcsc->context);
        if (rv != SCARD_S_SUCCESS) {
            return SIM_ERR_PCSC_DISCONNECT;
        }
        pcsc->context = 0;
    }
    return SIM_OK;
}

/* CCID: Initialize programmer */
static sim_error_t ccid_init(void *state) {
    ccid_programmer_t *ccid = (ccid_programmer_t *)state;
    int r = 0;

    r = libusb_init(&ccid->context);
    if (r < 0) {
        return SIM_ERR_CCID_INIT;
    }

    libusb_device **devs = NULL;
    ssize_t cnt = libusb_get_device_list(ccid->context, &devs);
    if (cnt < 0) {
        libusb_exit(ccid->context);
        return SIM_ERR_CCID_INIT;
    }

    for (ssize_t i = 0; i < cnt; i++) {
        struct libusb_device_descriptor desc = {0};
        libusb_get_device_descriptor(devs[i], &desc);
        if (desc.bDeviceClass == 0x0B || desc.bDeviceClass == LIBUSB_CLASS_PER_INTERFACE) {
            ccid->handle = libusb_open_device_with_vid_pid(ccid->context, desc.idVendor, desc.idProduct);
            if (ccid->handle) {
                if (libusb_claim_interface(ccid->handle, 0) == 0) {
                    libusb_free_device_list(devs, 1);
                    return SIM_OK;
                }
                libusb_close(ccid->handle);
                ccid->handle = NULL;
            }
        }
    }

    libusb_free_device_list(devs, 1);
    libusb_exit(ccid->context);
    return SIM_ERR_CCID_INIT;
}

/* CCID: Write SIM parameters */
static sim_error_t ccid_write(void *state, const sim_params_t *params) {
    ccid_programmer_t *ccid = (ccid_programmer_t *)state;
    if (params == NULL || ccid == NULL || ccid->handle == NULL) {
        return SIM_ERR_INVALID_PARAM;
    }

    uint8_t apdu[MAX_APDU_LEN] = {0};
    size_t apdu_len = 0;
    uint8_t response[MAX_APDU_LEN] = {0};
    int transferred = 0;

    uint8_t ccid_cmd[10 + MAX_APDU_LEN] = {
        0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    #define SEND_APDU(apdu_data, len) do { \
        ccid_cmd[1] = (len) & 0xFF; \
        ccid_cmd[2] = ((len) >> 8) & 0xFF; \
        ccid_cmd[3] = ((len) >> 16) & 0xFF; \
        ccid_cmd[4] = ((len) >> 24) & 0xFF; \
        memcpy(ccid_cmd + 10, apdu_data, len); \
        transferred = libusb_bulk_transfer(ccid->handle, 0x02, ccid_cmd, 10 + (len), &transferred, CCID_TIMEOUT_MS); \
        if (transferred < 0) return SIM_ERR_CCID_TRANSMIT; \
        transferred = libusb_bulk_transfer(ccid->handle, 0x81, response, MAX_APDU_LEN, &transferred, CCID_TIMEOUT_MS); \
        if (transferred < 2 || response[transferred - 2] != 0x90 || response[transferred - 1] != 0x00) \
            return SIM_ERR_CCID_TRANSMIT; \
    } while (0)

    uint8_t select_usim[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00};
    apdu_len = sizeof(select_usim);
    memcpy(apdu, select_usim, apdu_len);
    SEND_APDU(apdu, apdu_len);

    uint8_t imsi_bytes[9] = {0};
    if (strlen(params->imsi) != 15) {
        return SIM_ERR_INVALID_PARAM;
    }
    imsi_bytes[0] = 0x08;
    for (size_t i = 0; i < 8; i++) {
        char digit1 = params->imsi[2 * i];
        char digit2 = params->imsi[2 * i + 1];
        imsi_bytes[i + 1] = ((digit1 - '0') << 4) | (digit2 - '0');
    }
    uint8_t write_imsi[] = {0x00, 0xA4, 0x04, 0x00, 0x02, 0x6F, 0x07,
                            0x00, 0xDC, 0x01, 0x04, 0x09};
    memcpy(apdu, write_imsi, sizeof(write_imsi));
    memcpy(apdu + sizeof(write_imsi), imsi_bytes, 9);
    apdu_len = sizeof(write_imsi) + 9;
    SEND_APDU(apdu, apdu_len);

    uint8_t ki_bytes[16] = {0};
    if (hex_to_bytes(params->ki, ki_bytes, 16) != SIM_OK) {
        return SIM_ERR_INVALID_PARAM;
    }
    uint8_t write_ki[] = {0x00, 0xDC, 0x01, 0x04, 0x10};
    memcpy(apdu, write_ki, sizeof(write_ki));
    memcpy(apdu + sizeof(write_ki), ki_bytes, 16);
    apdu_len = sizeof(write_ki) + 16;
    SEND_APDU(apdu, apdu_len);

    uint8_t opc_bytes[16] = {0};
    if (hex_to_bytes(params->opc, opc_bytes, 16) != SIM_OK) {
        return SIM_ERR_INVALID_PARAM;
    }
    memcpy(apdu, write_ki, sizeof(write_ki));
    memcpy(apdu + sizeof(write_ki), opc_bytes, 16);
    apdu_len = sizeof(write_ki) + 16;
    SEND_APDU(apdu, apdu_len);

    #undef SEND_APDU
    return SIM_OK;
}

/* CCID: Close programmer */
static sim_error_t ccid_close(void *state) {
    ccid_programmer_t *ccid = (ccid_programmer_t *)state;
    if (ccid->handle != NULL) {
        libusb_release_interface(ccid->handle, 0);
        libusb_close(ccid->handle);
        ccid->handle = NULL;
    }
    if (ccid->context != NULL) {
        libusb_exit(ccid->context);
        ccid->context = NULL;
    }
    return SIM_OK;
}

/* Log error message */
static void log_error(const sim_state_t *state, const char *msg) {
    FILE *out = (state->log_file != NULL) ? state->log_file : stderr;
    fprintf(out, "ERROR: %s\n", msg);
    fflush(out);
}

/* Parse configuration file */
static sim_error_t parse_config(const char *filename, sim_params_t *params) {
    FILE *fp = NULL;
    char line[MAX_LINE_LEN] = {0};
    char key[32] = {0};
    char value[MAX_LINE_LEN] = {0};
    int found_imsi = 0, found_ki = 0, found_opc = 0, found_mcc = 0, found_mnc = 0;

    if (filename == NULL || params == NULL) {
        return SIM_ERR_INVALID_PARAM;
    }

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return SIM_ERR_FILE_OPEN;
    }

    params->imsi[0] = '\0';
    params->ki[0] = '\0';
    params->opc[0] = '\0';
    params->mcc[0] = '\0';
    params->mnc[0] = '\0';

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {
        if (line[0] == '\0' || line[0] == '#' || line[0] == '\n') {
            continue;
        }

        if (sscanf(line, "%31[^=]=%255[^\n]", key, value) != 2) {
            fclose(fp);
            return SIM_ERR_INVALID_CONFIG;
        }

        while (value[0] == ' ') {
            memmove(value, value + 1, strlen(value));
        }
        size_t len = strlen(value);
        while (len > 0 && (value[len - 1] == ' ' || value[len - 1] == '\n')) {
            value[len - 1] = '\0';
            len--;
        }

        if (strcmp(key, "imsi") == 0 && len < MAX_IMSI_LEN) {
            strncpy(params->imsi, value, MAX_IMSI_LEN - 1);
            params->imsi[MAX_IMSI_LEN - 1] = '\0';
            found_imsi = 1;
        } else if (strcmp(key, "ki") == 0 && len < MAX_KI_LEN) {
            strncpy(params->ki, value, MAX_KI_LEN - 1);
            params->ki[MAX_KI_LEN - 1] = '\0';
            found_ki = 1;
        } else if (strcmp(key, "opc") == 0 && len < MAX_OPC_LEN) {
            strncpy(params->opc, value, MAX_OPC_LEN - 1);
            params->opc[MAX_OPC_LEN - 1] = '\0';
            found_opc = 1;
        } else if (strcmp(key, "mcc") == 0 && len < MAX_MCC_LEN) {
            strncpy(params->mcc, value, MAX_MCC_LEN - 1);
            params->mcc[MAX_MCC_LEN - 1] = '\0';
            found_mcc = 1;
        } else if (strcmp(key, "mnc") == 0 && len < MAX_MNC_LEN) {
            strncpy(params->mnc, value, MAX_MNC_LEN - 1);
            params->mnc[MAX_MNC_LEN - 1] = '\0';
            found_mnc = 1;
        }
    }

    fclose(fp);

    if (!found_imsi || !found_ki || !found_opc || !found_mcc || !found_mnc) {
        return SIM_ERR_INVALID_CONFIG;
    }

    return SIM_OK;
}

/* Select programmer */
static sim_error_t select_programmer(const char *name, sim_state_t *state) {
    if (name == NULL || state == NULL) {
        return SIM_ERR_INVALID_PARAM;
    }

    for (size_t i = 0; i < MAX_PROGRAMMERS && programmers[i].name != NULL; i++) {
        if (strcmp(name, programmers[i].name) == 0) {
            state->driver = &programmers[i];
            return SIM_OK;
        }
    }
    return SIM_ERR_PROGRAMMER_NOT_FOUND;
}

/* Main function */
int main(int argc, char *argv[]) {
    sim_state_t state = { .log_file = NULL, .driver = NULL, .state = {0}, .esim_mode = 0, .srsran_mode = 0, .qr_output_file = {0} };
    sim_params_t params = {0};
    sim_error_t ret = SIM_OK;
    char error_msg[MAX_ERROR_MSG_LEN] = {0};
    int arg_offset = 1;

    if (argc < 3 || argc > 5) {
        fprintf(stderr, "Usage: %s <device> <config_file> [--esim <file>]\n", argv[0]);
        fprintf(stderr, "Device: PCSC, CCID\n");
        fprintf(stderr, "Use --esim <file> for eSIM QR code output.\n");
        return 1;
    }

    if (argc >= arg_offset + 3) {
        if (strcmp(argv[arg_offset + 2], "--esim") == 0 || strncmp(argv[arg_offset + 2], "--esim=", 7) == 0) {
            state.esim_mode = 1;
            if (strncmp(argv[arg_offset + 2], "--esim=", 7) == 0) {
                strncpy(state.qr_output_file, argv[arg_offset + 2] + 7, MAX_FILENAME_LEN - 1);
                state.qr_output_file[MAX_FILENAME_LEN - 1] = '\0';
            } else if (argc == arg_offset + 4) {
                strncpy(state.qr_output_file, argv[arg_offset + 3], MAX_FILENAME_LEN - 1);
                state.qr_output_file[MAX_FILENAME_LEN - 1] = '\0';
            } else {
                strncpy(state.qr_output_file, "esim.png", MAX_FILENAME_LEN - 1);
            }
        } else {
            fprintf(stderr, "Invalid option: %s\n", argv[arg_offset + 2]);
            return 1;
        }
    }

    ret = parse_config(argv[arg_offset + 1], &params);
    if (ret != SIM_OK) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Failed to parse config file '%s'", argv[arg_offset + 1]);
        log_error(&state, error_msg);
        return 1;
    }

    if (state.esim_mode) {
        ret = generate_esim_qr(&state, &params);
        if (ret != SIM_OK) {
            snprintf(error_msg, MAX_ERROR_MSG_LEN, "Failed to generate eSIM QR code: %d", ret);
            log_error(&state, error_msg);
            return 1;
        }
        printf("eSIM QR code generated: %s\n", state.qr_output_file);
        return 0;
    }

    ret = select_programmer(argv[arg_offset], &state);
    if (ret != SIM_OK) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Programmer '%s' not found", argv[arg_offset]);
        log_error(&state, error_msg);
        return 1;
    }

    ret = state.driver->init(&state.state);
    if (ret != SIM_OK) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Failed to initialize programmer: %d", ret);
        log_error(&state, error_msg);
        return 1;
    }

    ret = state.driver->write(&state.state, &params);
    if (ret != SIM_OK) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Failed to write SIM parameters: %d", ret);
        log_error(&state, error_msg);
        state.driver->close(&state.state);
        return 1;
    }

    ret = state.driver->close(&state.state);
    if (ret != SIM_OK) {
        snprintf(error_msg, MAX_ERROR_MSG_LEN, "Failed to close programmer: %d", ret);
        log_error(&state, error_msg);
        return 1;
    }

    printf("SIM card flashed successfully\n");
    return 0;
}
