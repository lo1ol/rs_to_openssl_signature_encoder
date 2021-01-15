#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "rs_to_openssl.h"

int main()
{       
        FILE *fptr;
        unsigned char sig[64];
        
        fptr = fopen("data.sig", "rb");
        fread(sig, 1, sizeof(sig), fptr);
        fclose(fptr);
        
        for (int i=0; i< sizeof(sig); ++i) {
                printf("%02x", sig[i]);
        }
        
        printf("\n");
        
        unsigned char *seq;
        size_t seqlen;
        
        if (sc_asn1_sig_value_rs_to_sequence(sig, sizeof(sig), &seq, &seqlen)) {
                printf("Failed to convert signature to ASN.1 sequence format\n");
        }
        for (int i=0; i< seqlen; ++i) {
                printf("%02x", seq[i]);
        }
        
        fptr = fopen("data.sig.openssl", "wb");
        int rv = fwrite(seq, 1, seqlen, fptr);
        fclose(fptr);
        printf("\n%d\n", rv);
        free(seq);
        return 0;
}
