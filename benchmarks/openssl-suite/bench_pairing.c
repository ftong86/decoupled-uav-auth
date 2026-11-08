#define _POSIX_C_SOURCE 200809L
#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef void (*op_fn)(void *);

typedef struct {
    pairing_t pairing;
    element_t P;
    element_t Q;
    element_t z;
    element_t g1_out;
    element_t gt_out;
    unsigned char msg[64];
} ctx_t;

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *x, int n) {
    qsort(x, n, sizeof(double), cmp_double);
    return (n & 1) ? x[n/2] : 0.5 * (x[n/2-1] + x[n/2]);
}

static double batch_time(op_fn fn, void *ctx, size_t batch) {
    double t0 = now_us();
    for (size_t i = 0; i < batch; ++i) fn(ctx);
    return now_us() - t0;
}

static void op_pair(void *p) {
    ctx_t *c = (ctx_t *)p;
    pairing_apply(c->gt_out, c->P, c->Q, c->pairing);
}

static void op_psm(void *p) {
    ctx_t *c = (ctx_t *)p;
    element_mul_zn(c->g1_out, c->P, c->z);
}

static void op_h2g(void *p) {
    ctx_t *c = (ctx_t *)p;
    element_from_hash(c->g1_out, c->msg, sizeof(c->msg));
}

static void bench_one(FILE *out, const char *name, const char *notes,
                      op_fn fn, void *ctx) {
    int runs = 21, samples = 31;
    const double target_sample_us = 2000.0;
    size_t batch = 1;

    for (int i = 0; i < 32; ++i) fn(ctx);

    double e = batch_time(fn, ctx, batch);
    while (e < target_sample_us && batch < (1u << 20)) {
        batch *= 2;
        e = batch_time(fn, ctx, batch);
    }

    double per = e / (double)batch;
    if (per > 5000.0) { runs = 11; samples = 11; }
    else if (per > 500.0) { runs = 15; samples = 15; }

    for (int r = 0; r < runs; ++r) {
        double *v = (double *)malloc((size_t)samples * sizeof(double));
        if (!v) exit(2);
        for (int s = 0; s < samples; ++s) {
            v[s] = batch_time(fn, ctx, batch) / (double)batch;
        }
        fprintf(out, "%s,%d,%.9f,%zu,\"%s\"\n",
                name, r+1, median(v, samples), batch, notes);
        free(v);
    }
}

static char *read_all(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) exit(2);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) exit(2);
    fclose(f);
    buf[sz] = '\0';
    *n = (size_t)sz;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s typea_256_1536.param [runs_pairing.csv]\n",
                argv[0]);
        return 1;
    }
    const char *out_path = (argc >= 3) ? argv[2] : "runs_pairing.csv";

    size_t n = 0;
    char *param = read_all(argv[1], &n);
    if (!param) {
        fprintf(stderr, "Cannot read parameter file: %s\n", argv[1]);
        return 1;
    }

    ctx_t c;
    if (pairing_init_set_buf(c.pairing, param, n)) {
        fprintf(stderr, "pairing_init_set_buf failed\n");
        free(param);
        return 1;
    }
    free(param);

    element_init_G1(c.P, c.pairing);
    element_init_G2(c.Q, c.pairing);
    element_init_Zr(c.z, c.pairing);
    element_init_G1(c.g1_out, c.pairing);
    element_init_GT(c.gt_out, c.pairing);

    element_random(c.P);
    element_random(c.Q);
    element_random(c.z);
    for (int i=0;i<64;++i) c.msg[i] = (unsigned char)(i + 1);

    FILE *out = fopen(out_path, "w");
    if (!out) {
        fprintf(stderr, "Cannot open %s\n", out_path);
        return 1;
    }
    fprintf(out, "primitive,run,median_us,batch_size,notes\n");

    bench_one(out, "T_BP_TYPEA_256_1536",
              "PBC Type-A bilinear pairing; rbits=256,qbits=1536; fixed parameter file",
              op_pair, &c);

    bench_one(out, "T_PSM_G1_TYPEA_256_1536",
              "PBC Type-A G1 scalar multiplication kP; rbits=256,qbits=1536",
              op_psm, &c);

    bench_one(out, "T_H2G_G1_TYPEA_256_1536",
              "PBC element_from_hash to G1 over a 64-byte message; rbits=256,qbits=1536",
              op_h2g, &c);

    fclose(out);

    element_clear(c.gt_out);
    element_clear(c.g1_out);
    element_clear(c.z);
    element_clear(c.Q);
    element_clear(c.P);
    pairing_clear(c.pairing);

    fprintf(stderr, "Wrote %s\n", out_path);
    return 0;
}
