#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <bcg729/decoder.h>

static bool read_exact(FILE *f, uint8_t *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        size_t r = fread(buf + got, 1, n - got, f);
        if (r == 0) return false;
        got += r;
    }
    return true;
}

/* Heuristic: detect SID (Annex B) vs speech frame by remaining bytes.
   Common RTP packing is 10-byte speech frames and 2-byte SID frames.
   If your capture uses multiple frames per packet, Wireshark’s “Save payload” already flattened them. */
static int next_frame_len(FILE *f) {
    int c = fgetc(f);
    if (c == EOF) return -1;
    ungetc(c, f);
    /* There is no explicit TOC here; we assume a stream of 10-byte frames
       with occasional 2-byte SID per RFC conventions for G.729 Annex B in RTP. */
    long pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long end = ftell(f);
    fseek(f, pos, SEEK_SET);
    long left = end - pos;
    if (left >= 10) return 10;
    if (left >= 2) return 2; /* likely SID at tail */
    return (int)left;        /* partial (treat as lost) */
}

int main(void) {
    bcg729DecoderChannelContextStruct *dec = initBcg729DecoderChannel();
    if (!dec) return 1;

    int16_t pcm[80]; /* 10 ms of 8 kHz mono = 80 samples */
    uint8_t buf[10]; /* max regular speech frame length */

    while (1) {
        int flen = next_frame_len(stdin);
        if (flen < 0) break;

        uint8_t bfi = 0;      /* 0: good frame, 1: bad/lost */
        uint8_t sidFrame = 0; /* 1: SID (Annex B) */
        uint8_t rfc3389_cng = 0;

        if (flen == 10) {
            if (!read_exact(stdin, buf, 10)) break;
            sidFrame = 0;
            bfi = 0;
            /* decode active speech */
            decodeBcg729(dec, buf, pcm, bfi, sidFrame, rfc3389_cng);
            fwrite(pcm, sizeof(int16_t), 80, stdout);
        } else if (flen == 2) {
            uint8_t sid[2];
            if (!read_exact(stdin, sid, 2)) break;
            sidFrame = 1;
            bfi = 0;
            /* decode SID frame — decoder outputs CNG */
            decodeBcg729(dec, sid, pcm, bfi, sidFrame, rfc3389_cng);
            fwrite(pcm, sizeof(int16_t), 80, stdout);
        } else {
            /* partial tail — do PLC once and exit */
            uint8_t dummy[10] = {0};
            bfi = 1; sidFrame = 0;
            decodeBcg729(dec, dummy, pcm, bfi, sidFrame, rfc3389_cng);
            fwrite(pcm, sizeof(int16_t), 80, stdout);
            break;
        }
    }

    closeBcg729DecoderChannel(dec);
    return 0;
}
