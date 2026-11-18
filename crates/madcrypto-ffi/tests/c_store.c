/* In-memory C contract fixture, never a production durable store. */
#include "madcrypto_store.h"
#include <stdlib.h>
#include <string.h>
#define MAX_RECORDS 16
struct record { uint8_t *scope,*operation,*data; size_t scope_len,op_len,len; uint64_t revision; };
struct fixture { struct record rows[MAX_RECORDS]; size_t count; int mode; };
void *madcrypto_store_fixture_new(void) { return calloc(1,sizeof(struct fixture)); }
void madcrypto_store_fixture_free(void *ctx) {
  struct fixture *f=ctx;
  for(size_t i=0;i<f->count;i++){free(f->rows[i].scope);free(f->rows[i].operation);free(f->rows[i].data);}
  free(f);
}
void madcrypto_store_fixture_mode(void *ctx,int mode){((struct fixture*)ctx)->mode=mode;}
static struct record *find(struct fixture *f,const uint8_t*s,size_t sn,const uint8_t*op,size_t on){
  for(size_t i=f->count;i>0;i--){struct record*r=&f->rows[i-1];if(r->scope_len==sn&&!memcmp(r->scope,s,sn)&&(!on||(r->op_len==on&&!memcmp(r->operation,op,on))))return r;}
  return NULL;
}
static int32_t load(void *ctx,const uint8_t*s,size_t sn,const uint8_t*op,size_t on,uint8_t*out,size_t cap,size_t*n){
  struct fixture*f=ctx;
  if(f->mode==1)return -2;
  if(f->mode==2){*n=3*1024*1024;return 0;}
  struct record*r=find(f,s,sn,op,on);if(!r)return 1;
  *n=r->len;if(!out)return 0;
  if(f->mode==6){*n=0;return 0;}
  if(f->mode==8)return 1;
  if(f->mode==9){*n=cap+1;return 0;} /* bogus length, NO overflow write */
  if(f->mode==10){*n=cap+1;return -3;} /* record grew since probe */
  if(cap<r->len)return -3;
  memcpy(out,r->data,r->len);
  if(f->mode==7)out[0]^=1;
  return 0;
}
static int32_t commit(void*ctx,const uint8_t*s,size_t sn,uint32_t has,uint64_t expected,uint64_t revision,const uint8_t*op,size_t on,const uint8_t*data,size_t n){
  struct fixture*f=ctx;struct record*latest=find(f,s,sn,NULL,0);
  if((has&&(!latest||latest->revision!=expected))||(!has&&latest)||find(f,s,sn,op,on))return 1;
  if(f->mode==11)return 2; /* definite rejection before any write */
  if(f->mode==3)return 3; /* unknown without write */
  if(f->count==MAX_RECORDS)return 2;
  struct record row={0};row.scope=malloc(sn);row.operation=malloc(on);row.data=malloc(n);
  if(!row.scope||!row.operation||!row.data){free(row.scope);free(row.operation);free(row.data);return 2;}
  memcpy(row.scope,s,sn);memcpy(row.operation,op,on);memcpy(row.data,data,n);row.scope_len=sn;row.op_len=on;row.len=n;row.revision=revision;
  f->rows[f->count++]=row;
  if(f->mode==4)return 3; /* unknown after write */
  if(f->mode==5)return 77; /* unfamiliar status must fail closed */
  return 0;
}
void madcrypto_store_fixture_api(void*ctx,madcrypto_store_v1*out){
  out->struct_size=sizeof(*out);out->abi_version=1;out->ctx=ctx;out->load=load;out->commit=commit;
}
