#include "probe.h"

#include "intel.h"
#include "arm.h"
#include "ppc.h"

int ceph_arch_probe(void)
{
  if (ceph_arch_probed)
    return 1;
#if defined(__i386__) || defined(__x86_64__)
  ceph_arch_intel_probe();
#elif defined(__arm__) || defined(__aarch64__)
  ceph_arch_arm_probe();
#elif defined(__powerpc__) || defined(__ppc__)
  ceph_arch_ppc_probe();
#endif
  ceph_arch_probed = 1;
  return 1;
}

// do this once using the magic of c++.
int ceph_arch_probed = ceph_arch_probe();
