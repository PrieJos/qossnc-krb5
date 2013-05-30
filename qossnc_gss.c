/* vim: set noet ai ts=4 sw=4: */

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>

#include "qossnc_gss.h"

OM_uint32 qossnc_gss_compare_oid(const gss_OID oid1, const gss_OID oid2)
{
	if (oid1)
		if (oid2)
			if (oid1->length == oid2->length 
				&& !memcmp(oid1->elements, oid2->elements, oid1->length))
				return GSS_S_COMPLETE;
			else
				return GSS_S_FAILURE;
		else
			return GSS_S_FAILURE;
	else
		if (oid2)
			return GSS_S_FAILURE;
		else
			return GSS_S_COMPLETE;
}

OM_uint32 qossnc_gss_copy_oid(gss_OID *out, const gss_OID in)
{
    gss_OID tmp = GSS_C_NO_OID;

    if (in) {
        tmp = (void *)malloc(sizeof(gss_OID_desc));
        if (tmp == NULL)
			return GSS_S_FAILURE;
        tmp->length = in->length;
        tmp->elements = (void *)malloc(tmp->length);
        if (tmp->elements == NULL) {
			free(tmp);
			return GSS_S_FAILURE;
		}
        memcpy(tmp->elements, in->elements, in->length);
    }

    *out = tmp;
    
    return GSS_S_COMPLETE;
}

OM_uint32 qossnc_gss_copy_oid_set(gss_OID_set *out, const gss_OID_set in)
{
	gss_OID_set copy;
	gss_OID in_oid, out_oid;
	int i, rc = GSS_S_COMPLETE;
	
	if (out == NULL)
		return GSS_S_FAILURE;

	if (in == NULL) {
		*out = GSS_C_NO_OID_SET;
		return GSS_S_COMPLETE;
	}

	copy = (gss_OID_set)calloc(1,sizeof(gss_OID_set_desc));
	if (copy == NULL)
		return GSS_S_FAILURE;

	copy->elements = (gss_OID)calloc(in->count,sizeof(gss_OID_desc));
	if (copy->elements == NULL) {
		rc = GSS_S_FAILURE;
		goto copy_error;
	}

	copy->count = 0;
	for (i = 0; i < in->count; i++) {
		in_oid = in->elements+i;
		out_oid = copy->elements+i;
		if (qossnc_gss_copy_oid(&out_oid, in_oid) == GSS_S_FAILURE) {
			rc = GSS_S_FAILURE;
			goto copy_error;
		}
		copy->count++;
	}

	*out = copy;

copy_error:
	if (rc != GSS_S_COMPLETE) {
		for (i = 0; i < copy->count; i++) {
			in_oid = copy->elements+i;
			if (!in_oid) {
				if (!in_oid->elements)
					free(in_oid->elements);
				free(in_oid);
			}
		}
		free(copy);
	}
		
	return rc; 
}

