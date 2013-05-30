/* vim: set noet ai ts=4 sw=4: */

#include <stdlib.h>
#include <krb5.h>
#include <gssapi/gssapi_generic.h>
#include <gssapi/gssapi_krb5.h>


static OM_uint32 qossnc_krb5_get_ktname(OM_uint32 *min_stat,
	krb5_context k5ctx, char **ktname) 
{
	size_t n = 32;
	krb5_error_code k5rc;
	
	for(;;) {
		if ((*ktname = (char *)calloc(n, sizeof(char))) == NULL) {		
			*min_stat = (OM_uint32)-2045022972L;
			return GSS_S_FAILURE;
		}
				
		k5rc = krb5_kt_default_name(k5ctx, *ktname, n);
		if (k5rc) {
			free(*ktname);
			*ktname = NULL;
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
	
	return GSS_S_COMPLETE;
}


OM_uint32 qossnc_krb5_register_keytab_for_acceptor(OM_uint32 *min_stat)
{
	OM_uint32 maj_stat, rc = GSS_S_COMPLETE;
	krb5_context k5ctx;
	char *ktname;

	krb5_init_context(&k5ctx);

	maj_stat = qossnc_krb5_get_ktname(min_stat, k5ctx, &ktname);
	if (maj_stat != GSS_S_COMPLETE) {
		krb5_free_context(k5ctx);
		return maj_stat;		
	}
	
	maj_stat = krb5_gss_register_acceptor_identity(ktname);
	if (maj_stat != GSS_S_COMPLETE)
		rc = maj_stat;
	
	krb5_free_context(k5ctx);
	free(ktname);
	*min_stat = 0;
	return rc;
}

