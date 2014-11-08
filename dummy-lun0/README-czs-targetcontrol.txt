!!! This iSCSI target is controlled by czs-targetcontrol, the Citon ZFS Seed !!!
!!! Injector control system                                                  !!!

LUN 0 is required by the FreeBSD iSCSI target server.  Do not use this LUN for
data storage.  This LUN is backed by a raw disk image file on the CZS Injector
workstation.  Replace with an alternate disk image if you prefer.

All other LUNs on this target are mapped to removable drives attached to the
CZS Injector station. 

