/*
 * hexdiff - hexadecimal differencing program
 *
 * Copyright 2018 Austin Roach <ahroach@gmail.com>
 * Copyright 2021 Radomír Polách <rp@t4d.cz>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sys/ioctl.h>

#define BUFFER_SIZE 256

inline size_t min(size_t a, size_t b) { return a < b ? a : b; }

// ANSI escape sequences
static const char ansi_green[]  = "\x1B""[32m";
static const char ansi_red[]    = "\x1B""[31m";
static const char ansi_reset[]  = "\x1B""[0m";
static const char empty_str[]   = "";

typedef struct {
    FILE *file;
    char *name;
    char *buf;
    char *cur;
    char *end;
    int eof;
    size_t size;
    size_t pos;
} fc_t;

void fc_open(fc_t* fc, char* name, size_t size) {
    fc->name = name;
    if ((fc->file = fopen(name, "r")) == NULL) {
        fprintf(stderr, "fopen: %s: %s\n", name, strerror(errno));
        exit(EXIT_FAILURE);
    }
    fc->size = size;
    fc->pos = 0;
    if ((fc->buf = (char *)malloc(sizeof(char)*size)) == NULL) {
        fprintf(stderr, "malloc: %zu: %s\n", size, strerror(errno));
        exit(EXIT_FAILURE);
    }
    fc->cur = fc->buf;
    fc->end = fc->buf;
    fc->eof = 0;
}

void fc_forcemove(fc_t* fc, size_t size) {
    if (size && fseeko(fc->file, size, 0) != 0) {
        fprintf(stderr, "fseek to 0x%zx in %s: %s\n", size, fc->name, strerror(errno));
        exit(EXIT_FAILURE);
    }
    fc->pos = size;
}

size_t fc_read(fc_t* fc, char** target, size_t size) {
    size_t used = fc->cur > fc->end ? 0 : fc->end - fc->cur;
    if (used < size && !fc->eof) {
        memmove(fc->buf, fc->cur, used);
        size_t free = fc->size - used;
        size_t read = fread(fc->buf + used, 1, free, fc->file);
        fc->cur = fc->buf;
        fc->end = fc->cur + used + read;
        fc->eof = free != read;
        used = fc->end - fc->cur;
    }

    *target = fc->cur;
    return used;
}

inline size_t fc_move(fc_t* fc, size_t size) {
    fc->pos += size;
    fc->cur += size;
}

inline int fc_eof(fc_t* fc) {
    return fc->eof;
}

inline size_t fc_pos(fc_t* fc) {
    return fc->pos;
}

void fc_close(fc_t* fc) {
    fclose(fc->file);
    free(fc->buf);
}

static int sigint_recv = 0;

static void sigint_handler(int signum)
{
    sigint_recv = 1;
}

static void show_help(char **argv, int verbose)
{
    fprintf(stderr,
            "Usage: %s [-vadsnh] [-n num] [-c num] [-w num] [-B num]\n"
            "       file1 file2 [pos1 [pos2]]\n",
            argv[0]);
    if (verbose) {
        fprintf(stderr,
               " -v, --verbose                  verbose\n"
               " -a, --all                      print all lines\n"
               " -d, --dense                    dense output\n"
               " -s, --nosame                   skip same lines\n"
               " -h, --help                     show help\n"
               " -n num, --length=num           maximum number of bytes to compare\n"
               " -c num, --bytes-width=num      number of bytes (columns) (default = 16)\n"
               " -C num, --bytes-search=num     number of bytes (columns) for search (default = 256)\n"
               " -w num, --width=num            force terminal width\n"
               " -B num, --buffer-size=num      number of bytes for read buffer (default = 10240)\n"
               " pos1                          starting offset for file1\n"
               " pos2                          starting offset for file2\n");
    }
    exit(EXIT_FAILURE);
}

static void printicize(char * buf, size_t n)
{
    // Convert non-ASCII printable values to '.'
    for (int i=0; i<n; ++i) if (buf[i]<0x20 || buf[i]>0x7e) buf[i] = '.';
}

static void print_same_side(char *buf, size_t n, size_t skip, size_t read, int flag_dense)
{
    printf("%s0x%010zx  ", ansi_reset, skip);
    for (int i=0;i<read;++i) {
        printf("%02hhx", buf[i]);
        if (!flag_dense) printf(" ");
    }
    for (int i=read;i<n;++i) {
        printf("  ");
        if (!flag_dense) printf(" ");
    }
    printf(" ");
    printicize(buf, n);
    for (int i=0;i<read;++i) printf("%c", buf[i]);
    for (int i=read;i<n;++i) printf(" ");
}

static void print_same(char *buf1, char *buf2, size_t n, size_t pos1, size_t pos2, size_t read1, size_t read2, int flag_dense)
{
    // Print the left side
    print_same_side(buf1, n, pos1, read1, flag_dense);
    printf("    ");
    // Print the right side
    print_same_side(buf2, n, pos2, read2, flag_dense);
}

static void print_diff_side(char *buf, const char **color, size_t n, size_t skip, size_t read, int flag_dense)
{
    printf("%s0x%010zx  ", ansi_red, skip);
    for (int i=0;i<read;++i) {
        printf("%s%02hhx", color[i], buf[i]);
        if (!flag_dense) printf(" ");
    }
    for (int i=read;i<n;++i) {
        printf("  ");
        if (!flag_dense) printf(" ");
    }
    printf(" ");
    printicize(buf, n);
    for (int i=0;i<read;++i) printf("%s%c", color[i], buf[i]);
    for (int i=read;i<n;++i) printf(" ");
}

static void print_diff(char *buf1, char *buf2, size_t n, size_t pos1, size_t pos2, size_t read1, size_t read2, int flag_dense)
{
    const char *color[BUFFER_SIZE];
    const char *color_last;

    // Assign escape sequences as appropriate for each byte
    for (int i = 0; i < n; i++) {
        color[i] = buf1[i] == buf2[i] ? ansi_green : ansi_red;
    }

    // Remove many redundant escape sequences
    color_last = color[0];

    if ((color[0] == ansi_red) && (color[7] == ansi_red)) {
        // Beginning of each section is preceded by the address
        // (always red), or by the last element of a preceding
        // section. As long as the beginning and ending elements are
        // both red, we can get rid of the escape sequence at the
        // beginning of the section.
        color[0] = empty_str;
    }

    for (int i = 1; i < n; i++) {
        if (color[i] == color_last) {
            color[i] = empty_str;
        } else {
            color_last = color[i];
        }
    }

    // Print the left side
    print_diff_side(buf1, color, n, pos1, read1, flag_dense);
    printf("    ");
    // Print the right side
    print_diff_side(buf2, color, n, pos2, read2, flag_dense);
    printf("%s", ansi_reset);
}

int fit_bytes(int width, int flag_dense) {
    return ((width/2*2) - (12+2+1)*2 - 3)/2/(3+!flag_dense); // TODO: wtf
}


int main(int argc, char **argv)
{
    int opt, buffer_size = 10240, bytes_width = 16, bytes_search = 256, chars_width = 0;
    static int flag_verbose = 0, flag_all = 0, flag_dense = 0, flag_nosame = 0;
    size_t max_len = 0, cnt = 0, eq_run = 0;
    char *fname1, *fname2;
    char *buf1, *buf2;
    size_t pos1, pos2;
    size_t read1, read2;
    struct sigaction sigint_action;
    struct winsize ws;
    fc_t fc1, fc2;

    ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);
    chars_width = ws.ws_col;

    // Parse the input arguments
    static struct option long_options[] =
        {
          {"verbose",       no_argument,       NULL, 'v'},
          {"all",           no_argument,       NULL, 'a'},
          {"dense",         no_argument,       NULL, 'd'},
          {"nosame",        no_argument,       NULL, 's'},
          {"length",        required_argument, NULL, 'n'},
          {"width",         required_argument, NULL, 'w'},
          {"bytes-width",   required_argument, NULL, 'c'},
          {"bytes-search",  required_argument, NULL, 'C'},
          {"buffer-size",   required_argument, NULL, 'B'},
          {"help",          no_argument,       NULL, 'h'},
          {0, 0, 0, 0}
        };

    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "vadsn:w:c:C:B:h", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'v':
            flag_verbose = 1;
            break;
        case 'a':
            flag_all = 1;
            break;
        case 'd':
            flag_dense = 1;
            break;
        case 's':
            flag_nosame = 1;
            break;
        case 'h':
            show_help(argv, 1);
            break;
        case 'c':
            chars_width = 0;
            bytes_width = strtoull(optarg, NULL, 0);
            if (bytes_width < 1) bytes_width = 16;
            if (bytes_search > 256) bytes_width = bytes_search;
            break;
        case 'C':
            bytes_search = strtoull(optarg, NULL, 0);
            break; 
        case 'B':
            buffer_size = strtoull(optarg, NULL, 0);
            break; 
        case 'w':
            chars_width = strtoull(optarg, NULL, 0);
            break;
        case 'n':
            max_len = strtoull(optarg, NULL, 0);
            break;
        case '?':
        default:
            show_help(argv, 0);
        }
    }

    if (chars_width) {
        bytes_width = fit_bytes(chars_width, flag_dense);
        if (bytes_width < 1) bytes_width = 1;
    }

    // Get the filenames and any skip values
    if ((argc - optind) < 2) show_help(argv, 0);
    fname1 = argv[optind++];
    fname2 = argv[optind++];
    pos1 = (optind < argc) ? strtoull(argv[optind++], NULL, 0) : 0;
    pos2 = (optind < argc) ? strtoull(argv[optind++], NULL, 0) : 0;
    if (optind < argc) {
        //Leftover arguments
        for (int i = optind; i < argc; i++) fprintf (stderr, "%s: unexpected option %s\n", argv[0], argv[i]);
        show_help(argv, 0);
    }

    fc_open(&fc1, fname1, buffer_size);
    fc_open(&fc2, fname2, buffer_size);
    fc_forcemove(&fc1, pos1);
    fc_forcemove(&fc2, pos2);

    // Set up signal handler for SIGINT
    sigint_action.sa_handler = sigint_handler;
    sigaction(SIGINT, &sigint_action, NULL);

    while (((fc_pos(&fc1) < max_len && fc_pos(&fc2) < max_len) || !max_len) && !sigint_recv) {
        read1 = min(bytes_search, fc_read(&fc1, &buf1, bytes_search));
        read2 = min(bytes_search, fc_read(&fc2, &buf2, bytes_search));
        int read1p = min(bytes_width, read1);
        int read2p = min(bytes_width, read2);
        int readcmp = min(read1p, read2p);
        if (!readcmp) break;

        if (!memcmp(buf1, buf2, readcmp)) {
            if ((!flag_nosame && !eq_run) || flag_all) {
                print_same(buf1, buf2, bytes_width, fc_pos(&fc1), fc_pos(&fc2), read1p, read2p, flag_dense);
                printf("\n");
            } else if (eq_run == 1) printf("...\n");
            eq_run++;
        } else {
            print_diff(buf1, buf2, bytes_width, fc_pos(&fc1), fc_pos(&fc2), read1p, read2p, flag_dense);
            printf("\n");
            eq_run = 0;
        }
        fc_move(&fc1, bytes_width);
        fc_move(&fc2, bytes_width);
    }

    fc_close(&fc1);
    fc_close(&fc2);

    return EXIT_SUCCESS;
}

// vim: ts=2 fdm=marker syntax=c expandtab sw=2
