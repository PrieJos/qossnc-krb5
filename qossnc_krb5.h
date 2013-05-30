/* vim: set noet ai ts=4 sw=4: */

#ifndef __QOSSNC_KRB5_H__
#define __QOSSNC_KRB5_H__

extern void qossnc_krb5_initialize(void);
extern void qossnc_krb5_free(void);
extern OM_uint32 qossnc_krb5_register_keytab_for_acceptor(OM_uint32 *min_stat);

#endif