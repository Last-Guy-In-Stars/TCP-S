#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/module.h>
#include "tcps.h"

typedef uint64_t fe[5];

static inline uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

static inline uint64_t load_le64(const uint8_t *p) {
    return (uint64_t)load_le32(p)|((uint64_t)load_le32(p+4)<<32);
}

static inline void store_le32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

static void fe_frombytes(fe h, const uint8_t *s) {
    h[0]=load_le64(s)&0x7ffffffffffffULL;
    h[1]=(load_le64(s+6)>>3)&0x7ffffffffffffULL;
    h[2]=(load_le64(s+12)>>6)&0x7ffffffffffffULL;
    h[3]=(load_le64(s+19)>>1)&0x7ffffffffffffULL;
    h[4]=(load_le64(s+24)>>12)&0x7ffffffffffffULL;
}

static void fe_tobytes(uint8_t *s, fe h) {
    for(int i=0;i<4;i++){int64_t c=(int64_t)h[i]>>51;h[i+1]+=(uint64_t)c;h[i]-=(uint64_t)c<<51;}
    uint64_t v0=h[0],v1=h[1],v2=h[2],v3=h[3],v4=h[4];
    s[0]=(uint8_t)v0;s[1]=(uint8_t)(v0>>8);s[2]=(uint8_t)(v0>>16);s[3]=(uint8_t)(v0>>24);
    s[4]=(uint8_t)(v0>>32);s[5]=(uint8_t)(v0>>40);s[6]=(uint8_t)(v0>>48);
    s[6]^=(uint8_t)(v1<<6);
    s[7]=(uint8_t)(v1>>2);s[8]=(uint8_t)(v1>>10);s[9]=(uint8_t)(v1>>18);
    s[10]=(uint8_t)(v1>>26);s[11]=(uint8_t)(v1>>34);s[12]=(uint8_t)(v1>>42);
    s[12]^=(uint8_t)(v2<<3);
    s[13]=(uint8_t)(v2>>5);s[14]=(uint8_t)(v2>>13);s[15]=(uint8_t)(v2>>21);
    s[16]=(uint8_t)(v2>>29);s[17]=(uint8_t)(v2>>37);s[18]=(uint8_t)(v2>>45);
    s[18]^=(uint8_t)(v3<<7);
    s[19]=(uint8_t)(v3>>1);s[20]=(uint8_t)(v3>>9);s[21]=(uint8_t)(v3>>17);
    s[22]=(uint8_t)(v3>>25);s[23]=(uint8_t)(v3>>33);s[24]=(uint8_t)(v3>>41);
    s[24]^=(uint8_t)(v4<<4);
    s[25]=(uint8_t)(v4>>4);s[26]=(uint8_t)(v4>>12);s[27]=(uint8_t)(v4>>20);
    s[28]=(uint8_t)(v4>>28);s[29]=(uint8_t)(v4>>36);s[30]=(uint8_t)(v4>>44);
    s[31]=(uint8_t)(v4>>52);
}

static void fe_copy(fe d,const fe s){for(int i=0;i<5;i++)d[i]=s[i];}
static void fe_add(fe h,const fe f,const fe g){for(int i=0;i<5;i++)h[i]=f[i]+g[i];}
static void fe_sub(fe h,const fe f,const fe g){for(int i=0;i<5;i++)h[i]=f[i]-g[i];}

static void fe_carry(fe h) {
    for(int i=0;i<4;i++){uint64_t c=h[i]>>51;h[i+1]+=c;h[i]&=0x7ffffffffffffULL;}
    uint64_t c=h[4]>>51;h[4]&=0x7ffffffffffffULL;h[0]+=c*19;
    for(int i=0;i<4;i++){uint64_t c2=h[i]>>51;h[i+1]+=c2;h[i]&=0x7ffffffffffffULL;}
    h[4]&=0x7ffffffffffffULL;
}

static void fe_mul(fe h,const fe f,const fe g) {
    __uint128_t t[5];
    t[0]=(__uint128_t)f[0]*g[0]+19*((__uint128_t)f[1]*g[4]+(__uint128_t)f[2]*g[3]+(__uint128_t)f[3]*g[2]+(__uint128_t)f[4]*g[1]);
    t[1]=(__uint128_t)f[0]*g[1]+(__uint128_t)f[1]*g[0]+19*((__uint128_t)f[2]*g[4]+(__uint128_t)f[3]*g[3]+(__uint128_t)f[4]*g[2]);
    t[2]=(__uint128_t)f[0]*g[2]+(__uint128_t)f[1]*g[1]+(__uint128_t)f[2]*g[0]+19*((__uint128_t)f[3]*g[4]+(__uint128_t)f[4]*g[3]);
    t[3]=(__uint128_t)f[0]*g[3]+(__uint128_t)f[1]*g[2]+(__uint128_t)f[2]*g[1]+(__uint128_t)f[3]*g[0]+19*(__uint128_t)f[4]*g[4];
    t[4]=(__uint128_t)f[0]*g[4]+(__uint128_t)f[1]*g[3]+(__uint128_t)f[2]*g[2]+(__uint128_t)f[3]*g[1]+(__uint128_t)f[4]*g[0];
    for(int i=0;i<5;i++)h[i]=(uint64_t)t[i];
    fe_carry(h);
}

static void fe_sq(fe h,const fe f){fe_mul(h,f,f);}

static void fe_cswap(fe f,fe g,uint64_t b) {
    uint64_t mask=(uint64_t)-(int64_t)(b&1);
    for(int i=0;i<5;i++){uint64_t t=mask&(f[i]^g[i]);f[i]^=t;g[i]^=t;}
}

static void fe_invert(fe out,const fe z) {
    fe a,b,c,d,e;
    fe_sq(a,z);fe_sq(b,a);fe_sq(b,b);fe_mul(b,z,b);fe_mul(a,a,b);
    fe_sq(c,a);fe_mul(b,c,b);fe_sq(c,b);
    for(int i=1;i<5;i++)fe_sq(c,c);
    fe_mul(b,c,b);fe_sq(c,b);
    for(int i=1;i<10;i++)fe_sq(c,c);
    fe_mul(c,c,b);fe_sq(d,c);
    for(int i=1;i<20;i++)fe_sq(d,d);
    fe_mul(d,d,c);fe_sq(d,d);
    for(int i=1;i<10;i++)fe_sq(d,d);
    fe_mul(b,d,b);fe_sq(d,b);
    for(int i=1;i<50;i++)fe_sq(d,d);
    fe_mul(d,d,b);fe_sq(e,d);
    for(int i=1;i<100;i++)fe_sq(e,e);
    fe_mul(e,e,d);fe_sq(e,e);
    for(int i=1;i<50;i++)fe_sq(e,e);
    fe_mul(b,e,b);fe_sq(b,b);
    for(int i=1;i<5;i++)fe_sq(b,b);
    fe_mul(out,a,b);
}

void curve25519_base(uint8_t pub[32],const uint8_t priv[32]) {
    static const uint8_t bp[32]={9};
    curve25519_shared(pub,priv,bp);
}

void curve25519_shared(uint8_t out[32],const uint8_t scalar[32],const uint8_t point[32]) {
    uint8_t sc[32];memcpy(sc,scalar,32);
    sc[0]&=248;sc[31]&=127;sc[31]|=64;
    fe x1;fe_frombytes(x1,point);
    fe x2={1,0,0,0,0},z2={0,0,0,0,0},x3,z3={1,0,0,0,0};
    fe_copy(x3,x1);
    uint64_t swap=0;
    for(int pos=254;pos>=0;pos--){
        uint64_t kt=(sc[pos/8]>>(pos%8))&1;
        swap^=kt;fe_cswap(x2,x3,swap);fe_cswap(z2,z3,swap);swap=kt;
        fe A,AA,B,BB,C,D,DA,CB,E;
        fe_add(A,x2,z2);fe_sq(AA,A);fe_sub(B,x2,z2);fe_sq(BB,B);
        fe_sub(E,AA,BB);fe_add(C,x3,z3);fe_sub(D,x3,z3);
        fe_mul(DA,D,A);fe_mul(CB,C,B);
        fe_add(x3,DA,CB);fe_sq(x3,x3);
        fe_sub(z3,DA,CB);fe_sq(z3,z3);fe_mul(z3,z3,x1);
        fe_mul(x2,AA,BB);
        fe a24={121666,0,0,0,0};
        fe_mul(z2,E,a24);fe_add(z2,z2,AA);fe_mul(z2,z2,E);
        fe_sub(z2,z2,x2);fe_sub(z2,z2,x2);
    }
    fe_cswap(x2,x3,swap);fe_cswap(z2,z3,swap);
    fe inv;fe_invert(inv,z2);fe_mul(x2,x2,inv);
    fe_tobytes(out,x2);
}

static inline uint32_t rotl32(uint32_t v,int n){return(v<<n)|(v>>(32-n));}

#define QR(a,b,c,d) do { \
    a+=b;d^=a;d=rotl32(d,16);c+=d;b^=c;b=rotl32(b,12); \
    a+=b;d^=a;d=rotl32(d,8);c+=d;b^=c;b=rotl32(b,7);  \
} while(0)

static void chacha20_block(uint32_t out[16],const uint32_t state[16]) {
    uint32_t w[16];memcpy(w,state,64);
    for(int i=0;i<10;i++){
        QR(w[0],w[4],w[8],w[12]);QR(w[1],w[5],w[9],w[13]);
        QR(w[2],w[6],w[10],w[14]);QR(w[3],w[7],w[11],w[15]);
        QR(w[0],w[5],w[10],w[15]);QR(w[1],w[6],w[11],w[12]);
        QR(w[2],w[7],w[8],w[13]);QR(w[3],w[4],w[9],w[14]);
    }
    for(int i=0;i<16;i++)out[i]=w[i]+state[i];
}

void chacha20_xor_stream(const uint8_t key[32],uint64_t pos,uint8_t *data,size_t len) {
    uint64_t block_num=pos/64;
    uint32_t skip=(uint32_t)(pos%64);
    uint32_t state[16];
    state[0]=0x61707865;state[1]=0x3320646e;state[2]=0x79622d32;state[3]=0x6b206574;
    state[4]=load_le32(key);state[5]=load_le32(key+4);
    state[6]=load_le32(key+8);state[7]=load_le32(key+12);
    state[8]=load_le32(key+16);state[9]=load_le32(key+20);
    state[10]=load_le32(key+24);state[11]=load_le32(key+28);
    state[12]=(uint32_t)block_num;state[13]=(uint32_t)(block_num>>32);
    state[14]=0;state[15]=0;
    uint8_t ks[64];size_t off=0;
    if(skip>0){
        uint32_t blk[16];chacha20_block(blk,state);
        for(int i=0;i<16;i++)store_le32(ks+i*4,blk[i]);
        state[12]++;if(!state[12])state[13]++;
        size_t avail=64-skip;size_t chunk=(avail<len)?avail:len;
        for(size_t j=0;j<chunk;j++)data[off++]^=ks[skip+j];
    }
    while(off<len){
        uint32_t blk[16];chacha20_block(blk,state);
        for(int i=0;i<16;i++)store_le32(ks+i*4,blk[i]);
        state[12]++;if(!state[12])state[13]++;
        size_t chunk=len-off;if(chunk>64)chunk=64;
        for(size_t j=0;j<chunk;j++)data[off++]^=ks[j];
    }
}

void tcps_derive_keys(const uint8_t shared[32],uint8_t key_out[32],uint8_t key_in[32]) {
    uint8_t master[32];memset(master,0,32);
    for(int i=0;i<32;i++)master[i%32]^=shared[i];
    uint8_t derived[64];memset(derived,0,64);
    uint8_t n1[8]={1,0,0,0,0,0,0,0};
    chacha20_xor_stream(master,0,derived,64);
    memcpy(key_out,derived,32);
    memset(derived,0,64);
    uint8_t n2[8]={2,0,0,0,0,0,0,0};
    chacha20_xor_stream(master,0,derived,64);
    memcpy(key_in,derived,32);
    memzero_explicit(master,sizeof(master));
    memzero_explicit(derived,sizeof(derived));
}

MODULE_LICENSE("GPL");
