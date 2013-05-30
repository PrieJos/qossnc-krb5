/* vim: set noet ai ts=4 sw=4: */

#ifndef __QOSSNC_GSS_H__
#define __QOSSNC_GSS_H__

extern OM_uint32 qossnc_gss_compare_oid(const gss_OID oid1, const gss_OID oid2);
extern OM_uint32 qossnc_gss_copy_oid(gss_OID *out, const gss_OID in);
extern OM_uint32 qossnc_gss_copy_oid_set(gss_OID_set *in, 
					const gss_OID_set out);

#endif