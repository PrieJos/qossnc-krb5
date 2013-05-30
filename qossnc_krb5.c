/* vim: set noet ai ts=4 sw=4: */

#include <stdlib.h>
#include <krb5.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>

#define SET_EMPTY_BUFFER(buf)	(buf)->length=0; (buf)->value = NULL


static krb5_context qossnc_krb5_ctx;
static gss_buffer_desc qossnc_krb5_ktname;


void qossnc_krb5_initialize(void)
{
	krb5_init_context(&qossnc_krb5_ctx);
	SET_EMPTY_BUFFER(&qossnc_krb5_ktname);
}


void qossnc_krb5_free(void)
{
	if (!GSS_EMPTY_BUFFER(&qossnc_krb5_ktname)) {
		free(qossnc_krb5_ktname.value);
		SET_EMPTY_BUFFER(&qossnc_krb5_ktname);
	}
	krb5_free_context(qossnc_krb5_ctx);
}


static OM_uint32 qossnc_krb5_init_ktname(OM_uint32 *min_stat) 
{
	size_t n = 32;
	char *ktname = NULL;
	krb5_error_code k5rc;
	
	for(;;) {
		if ((ktname = (char *)calloc(n, sizeof(char))) == NULL) {		
			*min_stat = (OM_uint32)-2045022972L;
			return GSS_S_FAILURE;
		}
				
		k5rc = krb5_kt_default_name(qossnc_krb5_ctx, ktname, n);
		if (k5rc) {
			free(ktname);
			SET_EMPTY_BUFFER(&qossnc_krb5_ktname);
			if (k5rc == KRB5_CONFIG_NOTENUFSPACE)
				n <<= 1;
			else {
				*min_stat = k5rc;
				return GSS_S_FAILURE;
			}
		}
		else
			break;
	}
	
	qossnc_krb5_ktname.length = n;
	qossnc_krb5_ktname.value = ktname;
	
	return GSS_S_COMPLETE;
}


OM_uint32 qossnc_krb5_register_keytab_for_acceptor(OM_uint32 *min_stat)
{
	OM_uint32 maj_stat;
	
	if (!qossnc_krb5_ktname.value) {
		maj_stat = qossnc_krb5_init_ktname(min_stat);
		if (maj_stat != GSS_S_COMPLETE)
			return maj_stat;		
	}
	
	maj_stat = krb5_gss_register_acceptor_identity(
				(char *)qossnc_krb5_ktname.value);
	if (maj_stat != GSS_S_COMPLETE) {
		*min_stat = 0;
		return maj_stat;
	}
	
	*min_stat = 0;
	return maj_stat;
}

