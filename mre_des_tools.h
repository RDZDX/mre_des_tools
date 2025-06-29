#ifndef _VRE_APP_WIZARDTEMPLATE_
#define	_VRE_APP_WIZARDTEMPLATE_

#include "vmio.h"
#include "string.h"
#include "stdint.h"
#include "vmdes.h"
#include "vmchset.h"
#include "vmstdlib.h"

void handle_sysevt(VMINT message, VMINT param);
VMINT job(VMWCHAR *FILE_PATH, VMINT wlen);
VMINT job1(VMWCHAR *FILE_PATH, VMINT wlen);
void save_text(VMINT state, VMWSTR text);
int utf8_char_length(unsigned char c);
int copy_utf8_safely(const char* input, unsigned char* output, int max_bytes);

#endif

