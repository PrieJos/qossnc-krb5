/* vim: set noet ai ts=4 sw=4: */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <gssapi/gssapi_krb5.h>

#include "qossnc_gss.h"
#include "qossnc_krb5.h"

#define STRINGIZEX(s)           #s
#define STRINGIZE(s)            STRINGIZEX(s)
#define UNREFERENCED_PARAMETER(a) \
			((a)=(a))

#ifdef QOSSNC_WINDOWS
#define EXPORT_FUNCTION
#else	/* QOSSNC_WINDOWS */
#define EXPORT_FUNCTION
#endif	/* QOSSNC_WINDOWS */

#ifdef QOSSNC_UNIX
#define CONSTRUCTOR_FUNCTION __attribute__((constructor))
#define DESTRUCTOR_FUNCTION __attribute__((destructor))
#else	/* QOSSNC_UNIX */
#define CONSTRUCTOR_FUNCTION
#define DESTRUCTOR_FUNCTION
#endif	/* QOSSNC_UNIX */


/*
 * qosIT SNC adapter definitions
 */
#define QOSSNC_MAJOR_REVISION	1
#define QOSSNC_MINOR_REVISION	0
#define QOSSNC_MECH_NAME		"MIT Kerberos 5 GSSAPI v2"
#define QOSSNC_MECH_PREFIX		"krb5" 	/* out of SNC adapter source code */ 
#define QOSSNC_MECH_ID 			2		/* out of SNC adapter source code */
#define QOSSNC_ADAPTER_NAME		"qosITconsulting SNC adapter " \
								"rev " STRINGIZE(QOSSNC_MAJOR_REVISION) \
								"." STRINGIZE(QOSSNC_MINOR_REVISION) " " \
								"for " QOSSNC_MECH_NAME
#define QOSSNC_CONF_AVAIL		1
#define QOSSNC_INTEG_AVAIL		1
#define QOSSNC_MUTUAL_AUTH		1
#define QOSSNC_REPLAY_PROT		1

static gss_OID_desc qossnc_oids[] = {
	/* Kerberos V5 RFC-1964 GSSAPI mechanism */
	{9, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"},

	/* Kerberos V5 pre-RFC-1964 GSSAPI mechanism */
	{5, "\x2b\x05\x01\x05\x02"},

	/* RFC-1964: GSS_KRB5_NT_PRINCIPAL_NAME */
	{10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01"},

	/* RFC-1964: GSS_C_NT_HOSTBASED_SERVICE */
	{10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04"},

	/* RFC-2473: GSS_C_NT_EXPORT_NAME */
	{6, "\x2b\x06\x01\x05\x06\x04"},
};
static gss_OID const qossnc_mech_oid = (gss_OID)qossnc_oids+0;
static gss_OID const qossnc_nt_oid = (gss_OID)qossnc_oids+2;
static gss_OID_set_desc const qossnc_mech_oids = {
	.count = 2,
	.elements = (gss_OID)qossnc_oids+0,
};


/*
 * SAP SNC adapter defintions
 */
struct sapgss_info_s {				/* out of SNC adapter source code       */
	int             major_rev;      /* major revision number of SNC-Adapter */
	int             minor_rev;      /* minor revision number of SNC-Adapter */
	char           	*adapter_name;  /* SNC-Adapter identification string    */
	int				mech_id;        /* SAP-registered gssapi mechanism      */
									/* identifier                           */
	char            integ_avail;    /* gssapi mechanism supports integrity  */
									/* protection                           */
	char            conf_avail;     /* gssapi mechanism supports            */
									/* confidentiality protection           */
	char            unused1;        /* historic -- not used  --  MUST BE 0  */
	char            export_sec_context;
									/* gssapi mechanism supports exporting  */
									/* of an established security context,  */
									/* as defined by GSS-API v2             */
	OM_uint32       unused2;        /* historic -- not used  --  MUST BE 0  */
	gss_OID_desc	*nt_canonical_name;
	gss_OID_desc 	*nt_private_name1;
	gss_OID_desc	*nt_private_name2;
	gss_OID_desc	*nt_private_name3;
	gss_OID_desc	*nt_private_name4;
	char			*mech_prefix_string;
	char 			mutual_auth;    /* gssapi mechanism supports mutual     */
									/* authentication                       */
	char			replay_prot;    /* gssapi mechanism supports replay     */
									/* detection                            */
	char 			reserved1;
	char 			reserved2;
	gss_OID_desc 	*mech_oid;
};

#define SAPGSS_INFO_LEN(x) ( \
	offsetof(struct sapgss_info_s, x) + \
	sizeof(((struct sapgss_info_s *)0)->x) \
)
#define SAPGSS_INFO_LEN_BASIC SAPGSS_INFO_LEN(replay_prot)


/*
 * qosIT SNC library constructor and destructor 
 */
static void __library_attach(void) CONSTRUCTOR_FUNCTION;
static void __library_detach(void) DESTRUCTOR_FUNCTION;

static void __library_attach(void)
{
	/* ToDo:
	 * initialize trace library
	 */
	qossnc_krb5_initialize();
	return;
}

static void __library_detach(void)
{
	/* ToDo:
	 * deinitialize trace library
	 */
	qossnc_krb5_free();
	return;
}

/*************************************
 **** qosIT SNC adapter functions ****
 *************************************/

/* 
 * specific SNC adapter functions 
 */
OM_uint32 EXPORT_FUNCTION
sapsnc_init_adapter(struct sapgss_info_s *p_info, size_t p_length,
	int adapter_idx)
{
	UNREFERENCED_PARAMETER(adapter_idx);

	if (p_info == NULL || p_length <= SAPGSS_INFO_LEN_BASIC) {
		return 1;
	} else {
		memset(p_info, 0, p_length);
		p_info->major_rev 			= (int) QOSSNC_MAJOR_REVISION;
		p_info->minor_rev 			= (int) QOSSNC_MINOR_REVISION;
		p_info->adapter_name 		= QOSSNC_ADAPTER_NAME;
		p_info->mech_id				= QOSSNC_MECH_ID;
		p_info->nt_canonical_name 	= qossnc_nt_oid;
		p_info->nt_private_name1 	= qossnc_nt_oid;
		p_info->nt_private_name2 	= (gss_OID_desc *)0;
		p_info->nt_private_name3 	= (gss_OID_desc *)0;
		p_info->nt_private_name4 	= (gss_OID_desc *)0;
		p_info->integ_avail 		= QOSSNC_INTEG_AVAIL;
		p_info->conf_avail 			= QOSSNC_CONF_AVAIL;
		p_info->unused1 			= 0; /* MUST be 0 */
		p_info->export_sec_context 	= 1; /* MUST be 1 */
		p_info->mutual_auth 		= QOSSNC_MUTUAL_AUTH;
		p_info->replay_prot			= QOSSNC_REPLAY_PROT;
		p_info->unused2 			= 0; /* MUST be 0 */
		p_info->mech_prefix_string 	= QOSSNC_MECH_PREFIX;

		if (p_length >= SAPGSS_INFO_LEN(mech_oid)) {
			p_info->mech_oid = qossnc_mech_oid;
		}
   }

   return 0;
}


/*
 * historical SNC adapter function
 * leave it up as is
 */
OM_uint32 EXPORT_FUNCTION
sapsnc_export_cname_blob(OM_uint32 *min_stat, gss_name_t in_name,
	gss_buffer_t out_identity, int adapter_idx)
{
	UNREFERENCED_PARAMETER(adapter_idx);
	UNREFERENCED_PARAMETER(in_name);

	if (out_identity != NULL) {
		out_identity->length = 0;
		out_identity->value  = NULL;
	}

	if (min_stat != NULL)
		(*min_stat) = 0;

	return GSS_S_FAILURE;
} 


/*
 * historical SNC adapter function
 * leave it up as is
 */
OM_uint32 EXPORT_FUNCTION
sapsnc_import_cname_blob(OM_uint32 *min_stat, gss_buffer_t in_identity,
	gss_name_t *out_name, int adapter_idx)
{
	UNREFERENCED_PARAMETER(adapter_idx);
	return gss_import_name(min_stat, in_identity,
				qossnc_nt_oid, out_name);
}


/*
 * GSS-API v1 (RFC 1508/1509)
 */

OM_uint32 EXPORT_FUNCTION
sapgss_acquire_cred(OM_uint32 *min_stat, gss_name_t  my_gss_name,
	OM_uint32 in_lifetime, gss_OID_set in_mechs,
	gss_cred_usage_t in_cred_usage, gss_cred_id_t  *out_cred,
	gss_OID_set *out_mechs, OM_uint32 *out_lifetime)
{
	OM_uint32 maj_stat;
	
	if (in_mechs == GSS_C_NO_OID_SET)
		in_mechs = (gss_OID_set)&qossnc_mech_oids;
		
	if (in_cred_usage == GSS_C_ACCEPT || in_cred_usage == GSS_C_BOTH) {
		maj_stat = qossnc_krb5_register_keytab_for_acceptor(min_stat);
		if (maj_stat != GSS_S_COMPLETE)
			return maj_stat;
	}
	
	maj_stat = gss_acquire_cred(min_stat, my_gss_name, in_lifetime, 
				in_mechs, in_cred_usage, out_cred, out_mechs, out_lifetime);
	if (maj_stat != GSS_S_COMPLETE)
		return maj_stat;
	
	return gss_inquire_cred(min_stat, *out_cred, NULL, 
				out_lifetime, NULL, NULL);
}


OM_uint32 EXPORT_FUNCTION
sapgss_release_cred(OM_uint32 * min_stat, gss_cred_id_t *in_cred)
{
	return gss_release_cred(min_stat, in_cred);
}


OM_uint32 EXPORT_FUNCTION
sapgss_init_sec_context(OM_uint32 *min_stat, gss_cred_id_t in_cred,	
	gss_ctx_id_t *in_context, gss_name_t in_name, gss_OID in_mech,
	OM_uint32 in_service_opts, OM_uint32 in_lifetime, 
	gss_channel_bindings_t in_channel_bind, gss_buffer_t in_token,
	gss_OID *out_mech, gss_buffer_t out_token, OM_uint32 *out_service_opts,	
	OM_uint32 *out_lifetime)
{
	return gss_init_sec_context(min_stat, in_cred, in_context, in_name,
					in_mech, in_service_opts, in_lifetime, in_channel_bind,
					in_token, out_mech, out_token, out_service_opts,
					out_lifetime);
}


OM_uint32 EXPORT_FUNCTION
sapgss_accept_sec_context(OM_uint32 *min_stat, gss_ctx_id_t *in_context,
	gss_cred_id_t in_cred, gss_buffer_t in_token, 
	gss_channel_bindings_t in_channel_bind,	gss_name_t *peer_name,
	gss_OID *out_mech, gss_buffer_t out_token, OM_uint32 *out_service_opts,
	OM_uint32 *out_lifetime, gss_cred_id_t *out_cred)
{
	return gss_accept_sec_context(min_stat, in_context, in_cred, in_token,
					in_channel_bind, peer_name, out_mech, out_token, 
					out_service_opts, out_lifetime, out_cred);
}


OM_uint32 EXPORT_FUNCTION
sapgss_process_context_token(OM_uint32 *min_stat, gss_ctx_id_t in_context,
	gss_buffer_t in_token)
{
	return gss_process_context_token(min_stat, in_context, in_token);
}


OM_uint32 EXPORT_FUNCTION
sapgss_delete_sec_context(OM_uint32 *min_stat, gss_ctx_id_t *in_context,
	gss_buffer_t out_token)
{
	return gss_delete_sec_context(min_stat, in_context, out_token);
}


OM_uint32 EXPORT_FUNCTION
sapgss_context_time(OM_uint32 *min_stat, gss_ctx_id_t in_context,
	OM_uint32 *out_lifetime)
{
	return gss_context_time(min_stat, in_context, out_lifetime);
}


OM_uint32 EXPORT_FUNCTION
sapgss_get_mic(OM_uint32 *min_stat,	gss_ctx_id_t in_context,
	gss_qop_t in_qop, gss_buffer_t in_msg, gss_buffer_t out_token)
{
	return gss_get_mic(min_stat, in_context, in_qop, in_msg, out_token);
}


OM_uint32 EXPORT_FUNCTION
sapgss_verify_mic(OM_uint32 *min_stat, gss_ctx_id_t in_context,
	gss_buffer_t in_msg, gss_buffer_t in_token, gss_qop_t *out_qop)
{
	return gss_verify_mic(min_stat, in_context, in_msg, in_token, out_qop);
}


OM_uint32 EXPORT_FUNCTION
sapgss_wrap(OM_uint32 *min_stat, gss_ctx_id_t in_context, int in_want_conf,
	gss_qop_t in_qop, gss_buffer_t in_msg, int *out_is_conf,
	gss_buffer_t out_token)
{
	return gss_wrap(min_stat, in_context, in_want_conf, in_qop, in_msg, 
				out_is_conf, out_token);
}


OM_uint32 EXPORT_FUNCTION
sapgss_unwrap(OM_uint32 *min_stat, gss_ctx_id_t in_context,	
	gss_buffer_t in_token, gss_buffer_t out_msg, int *out_is_conf,
	gss_qop_t *out_qop)
{
	return gss_unwrap(min_stat, in_context, in_token, out_msg, 
				out_is_conf, out_qop);
}


OM_uint32 EXPORT_FUNCTION
sapgss_display_status(OM_uint32 *min_stat, OM_uint32 in_status, 	
	int in_status_type, gss_OID in_mech, OM_uint32 *out_more_text,
	gss_buffer_t out_text)
{
	return gss_display_status( min_stat, in_status, in_status_type,
				in_mech, out_more_text, out_text);
}


/*
 * IMPORTANT: sapgss_indicate_mechs call MUST return the correct mech OID
 * for this implementation in the first position of the out_mechs OID array.
 * This is why array is rearrange after GSSAPI original call
 */
OM_uint32 EXPORT_FUNCTION
sapgss_indicate_mechs(OM_uint32 *min_stat, gss_OID_set *out_mechs)
{
	OM_uint32 maj_stat;
	int i;
	gss_OID mech, mech_tmp;
	
	maj_stat = gss_indicate_mechs(min_stat, out_mechs);
	if (maj_stat != GSS_S_COMPLETE)
		return maj_stat;
		
	/* rearrange output mechanism array according to instructions on SNC
	 * adapter
	 */
	for (i=0; i<(*out_mechs)->count; i++) {
		mech = (*out_mechs)->elements+i;
		if (qossnc_gss_compare_oid(mech, qossnc_mech_oid) == GSS_S_COMPLETE) {
			if (i > 0) {
				mech_tmp = (*out_mechs)->elements;
				(*out_mechs)->elements = mech;
				mech = mech_tmp;
			}
			break;
		}
	}
	
	return maj_stat;
}


OM_uint32 EXPORT_FUNCTION
sapgss_compare_name(OM_uint32 *min_stat, gss_name_t in_name1,
	gss_name_t in_name2, int *out_are_equal)
{
	return gss_compare_name(min_stat, in_name1, in_name2, out_are_equal);
}


OM_uint32 EXPORT_FUNCTION
sapgss_display_name(OM_uint32 *min_stat, gss_name_t in_name,
	gss_buffer_t out_identity, gss_OID *out_oid)
{
	return gss_display_name(min_stat, in_name, out_identity, out_oid);
}


OM_uint32 EXPORT_FUNCTION
sapgss_import_name(OM_uint32 *min_stat, gss_buffer_t in_identity,
	gss_OID in_oid, gss_name_t *out_name)
{
	return gss_import_name(min_stat, in_identity, in_oid, out_name);
}


OM_uint32 EXPORT_FUNCTION
sapgss_release_name(OM_uint32 *min_stat, gss_name_t *in_name)
{
	return gss_release_name(min_stat, in_name);
}


OM_uint32 EXPORT_FUNCTION
sapgss_release_buffer(OM_uint32 *min_stat, gss_buffer_t in_buffer)
{
	return gss_release_buffer(min_stat, in_buffer);
}


OM_uint32 EXPORT_FUNCTION
sapgss_release_oid_set(OM_uint32 *min_stat, gss_OID_set *in_oids)
{
	return gss_release_oid_set(min_stat, in_oids);
}


OM_uint32 EXPORT_FUNCTION
sapgss_inquire_cred(OM_uint32 *min_stat, gss_cred_id_t in_cred,
	gss_name_t *out_name, OM_uint32 *out_lifetime, 
	gss_cred_usage_t *out_cred_usage, gss_OID_set *out_mechs)
{
	return gss_inquire_cred( min_stat, in_cred, out_name, out_lifetime, 
				out_cred_usage, out_mechs);
}


/*
 * GSS-API v2 (RFC 2743)
 */

/* status:  not used by SNC in R/3 release 3.x and 4.0 */
OM_uint32 EXPORT_FUNCTION
sapgss_add_cred(OM_uint32 *min_stat, gss_cred_id_t input_cred_handle,
	gss_name_t desired_name, gss_OID desired_mech, gss_cred_usage_t cred_usage, 
	OM_uint32 initiator_time_req, OM_uint32 acceptor_time_req,
	gss_cred_id_t *output_cred_handle, gss_OID_set *actual_mechs,
	OM_uint32 *initiator_time_rec, OM_uint32 *acceptor_time_rec)
{
	return gss_add_cred(min_stat, input_cred_handle, desired_name,
				desired_mech, cred_usage, initiator_time_req, acceptor_time_req,
				output_cred_handle, actual_mechs, initiator_time_rec, 
				acceptor_time_rec);
}


/* status:  not used by SNC in R/3 release 3.x and 4.0
 *          this may change in future releases
 */
OM_uint32 EXPORT_FUNCTION
sapgss_inquire_cred_by_mech(OM_uint32 *min_stat, gss_cred_id_t cred_handle,
	gss_OID mech_type, gss_name_t *name, OM_uint32 *initiator_lifetime,
	OM_uint32 *acceptor_lifetime, gss_cred_usage_t *cred_usage)
{
	return gss_inquire_cred_by_mech(min_stat, cred_handle, mech_type, name, 
				initiator_lifetime, acceptor_lifetime, cred_usage);
}


OM_uint32 EXPORT_FUNCTION
sapgss_inquire_context(OM_uint32 *min_stat, gss_ctx_id_t in_context,
	gss_name_t *out_myname, gss_name_t *out_peername, OM_uint32 *out_lifetime,
	gss_OID *out_mech, OM_uint32 *out_service_opts, int *out_initiator,
	int *out_open)
{
	return gss_inquire_context(min_stat, in_context, out_myname, out_peername, 
				out_lifetime, out_mech, out_service_opts, out_initiator, 
				out_open);
}


/* status:  not used by SNC in R/3 release 3.x and 4.0
 *          this may change in future releases
 */
OM_uint32 EXPORT_FUNCTION
sapgss_wrap_size_limit(OM_uint32 *min_stat, gss_ctx_id_t in_context,
	int in_want_conf, gss_qop_t qop_req, OM_uint32 out_size, 
	OM_uint32 *max_in_size)
{
	return gss_wrap_size_limit(min_stat, in_context, in_want_conf,
				qop_req, out_size, max_in_size);
}


OM_uint32 EXPORT_FUNCTION
sapgss_export_sec_context(OM_uint32 *min_stat, gss_ctx_id_t  *in_ctx,
	gss_buffer_t out_buffer)
{
	return gss_export_sec_context(min_stat, in_ctx, out_buffer);
}


OM_uint32 EXPORT_FUNCTION
sapgss_import_sec_context(OM_uint32 *min_stat, gss_buffer_t in_buffer,
	gss_ctx_id_t *out_ctx)
{
	return gss_import_sec_context(min_stat, in_buffer, out_ctx);
}


OM_uint32 EXPORT_FUNCTION
sapgss_create_empty_oid_set(OM_uint32 *min_stat, gss_OID_set *oid_set)
{
	return gss_create_empty_oid_set(min_stat, oid_set);
}


/* status: don't care */
OM_uint32 EXPORT_FUNCTION
sapgss_add_oid_set_member(OM_uint32 *min_stat, gss_OID member_oid,
	gss_OID_set *oid_set)
{
	return gss_add_oid_set_member(min_stat, member_oid, oid_set);
}


/* status: don't care */
OM_uint32 EXPORT_FUNCTION
sapgss_test_oid_set_member(OM_uint32 *min_stat, gss_OID member, 
	gss_OID_set set, int *present)
{
	return gss_test_oid_set_member(min_stat, member, set, present);
}


OM_uint32 EXPORT_FUNCTION
sapgss_inquire_names_for_mech(OM_uint32	*min_stat, gss_OID mech_oid, 
	gss_OID_set *name_types)
{
	return gss_inquire_names_for_mech(min_stat, mech_oid, name_types);
}


/* status: don't care */
OM_uint32 EXPORT_FUNCTION
sapgss_inquire_mechs_for_name(OM_uint32 *min_stat,	gss_name_t input_name, 
	gss_OID_set *mech_set)
{
   return gss_inquire_mechs_for_name(min_stat, input_name, mech_set);
}


OM_uint32 EXPORT_FUNCTION
sapgss_canonicalize_name(OM_uint32 *min_stat, gss_name_t input_name,
	gss_OID mech_type,	gss_name_t *output_name)
{
	return gss_canonicalize_name(min_stat, input_name, mech_type, 
				output_name);
}


OM_uint32 EXPORT_FUNCTION
sapgss_export_name(OM_uint32 *min_stat,	gss_name_t input_name,
	gss_buffer_t output_name_blob)
{
	return gss_export_name(min_stat, input_name, output_name_blob);
}


/* status: Don't care */
OM_uint32 EXPORT_FUNCTION
sapgss_duplicate_name(OM_uint32 *min_stat, gss_name_t src_name,
	gss_name_t *dest_name)
{
	return gss_duplicate_name(min_stat, src_name, dest_name);
}
