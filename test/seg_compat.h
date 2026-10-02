#ifndef _HOMA_SEG_COMPAT_H
#define _HOMA_SEG_COMPAT_H

 /* Enforce plain (non-segment) per-CPU path selection to skip the __seg_gs
  * named address space.
 */
#undef CONFIG_CC_HAS_NAMED_AS
#undef CONFIG_USE_X86_SEG_SUPPORT

#endif
