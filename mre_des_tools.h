#ifndef _VRE_APP_WIZARDTEMPLATE_
#define	_VRE_APP_WIZARDTEMPLATE_

#include "vmio.h"
#include "string.h"
#include "stdint.h"
#include "vmdes.h"

#include "vmchset.h"
#include "vmstdlib.h"

#define CHUNK_SIZE 768

void handle_sysevt(VMINT message, VMINT param);
VMINT job(VMWCHAR *FILE_PATH, VMINT wlen);
VMINT job1(VMWCHAR *FILE_PATH, VMINT wlen);
void save_text(VMINT state, VMWSTR text);

#endif

