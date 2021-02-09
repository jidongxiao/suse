#ifndef IOC_H
#define IOC_H


#ifndef __KERNEL__
#define __user
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif

#include "cacheCryptoMain.h"


#define IsoToken_IOC_ID 'k'

#define IsoToken_IOC_SET_MASTER_KEY	_IOW(IsoToken_IOC_ID,0,int)
#define IsoToken_IOC_GET_PRIVATE_KEY_ID_NUM	_IOR(IsoToken_IOC_ID,1,int)
#define IsoToken_IOC_GET_PRIVATE_KEY_ID	_IOR(IsoToken_IOC_ID,1,uint8_t[KEY_ID_LEN])
#define IsoToken_IOC_SIGN	_IOWR(IsoToken_IOC_ID,2,uint8_t[MAX_MOD])

#define IsoToken_IOC_GET_PUBKEY	_IOWR(IsoToken_IOC_ID,3,uint8_t[MAX_MOD])

//#define IsoToken_IOC_SIGN_REQUEST	_IOW(IsoToken_IOC_ID,2,uint8_t[MAX_MOD])
//#define IsoToken_IOC_GET_SIGN_RESULT	_IOR(IsoToken_IOC_ID,3,uint8_t[MAX_MOD])

//#define IsoToken_IOC_SET_PRI_KEY	_IOW(IsoToken_IOC_ID,4,struct WRAPPED_PRI_KEY)
//#define IsoToken_IOC_SIGN_INIT	_IO(IsoToken_IOC_ID,5)
//#define IsoToken_IOC_SIGN_UPDATE	_IOW(IsoToken_IOC_ID,6,int)
//#define IsoToken_IOC_SIGN_FINAL	_IOR(IsoToken_IOC_ID,7,int)

#endif
