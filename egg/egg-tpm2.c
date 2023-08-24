/* libsecret - TSS interface implementations for libsecret
 *
 * Copyright (C) 2021 Dhanuka Warusadura
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301  USA
 *
 * Author: Dhanuka Warusadura
*/

#include "config.h"
#include "egg-tpm2.h"
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_tctildr.h>

#define MAX_BYTE_SIZE 64

struct EggTpm2Context {
	TSS2_TCTI_CONTEXT *tcti_context;
	ESYS_CONTEXT *esys_context;
	ESYS_TR primary_key;
};

static gboolean
egg_tpm2_generate_primary_key(EggTpm2Context *context,
		              GError **error)
{
	TSS2_RC ret;

	TPM2B_SENSITIVE_CREATE sensitive_params = {
		.size = 0,
		.sensitive = {
			.userAuth = {
				.size = 0,
				.buffer = {0},
			},
			.data = {
				.size = 0,
				.buffer = {0},
			},
		},
	};

	TPM2B_PUBLIC public_key_param = {
		.size = 0,
		.publicArea = {
			.type = TPM2_ALG_RSA,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (
				TPMA_OBJECT_USERWITHAUTH |
				TPMA_OBJECT_RESTRICTED |
				TPMA_OBJECT_DECRYPT |
				TPMA_OBJECT_FIXEDTPM |
				TPMA_OBJECT_FIXEDPARENT |
				TPMA_OBJECT_SENSITIVEDATAORIGIN),
			.authPolicy = {
				.size = 0,
			},
			.parameters.rsaDetail = {
				.symmetric = {
					.algorithm = TPM2_ALG_AES,
					.keyBits.aes = 128,
					.mode.aes = TPM2_ALG_CFB
				},
				.scheme = {
					.scheme = TPM2_ALG_NULL
				},
				.keyBits = 2048,
				.exponent = 0,
			},
			.unique.rsa = {
				.size = 0,
				.buffer = {},
			},
		},
	};

	TPM2B_DATA outside_info = {
		.size = 0,
		.buffer = {},
	};

	TPML_PCR_SELECTION pcrs = {
		.count = 0,
	};

	TPM2B_PUBLIC *public;
	TPM2B_CREATION_DATA *creation_data;
	TPM2B_DIGEST *hash;
	TPMT_TK_CREATION *ticket;

	ret = Esys_CreatePrimary(context->esys_context, ESYS_TR_RH_OWNER,
			         ESYS_TR_PASSWORD, ESYS_TR_NONE,
				 ESYS_TR_NONE, &sensitive_params,
				 &public_key_param, &outside_info,
				 &pcrs, &context->primary_key, &public,
				 &creation_data, &hash, &ticket);

	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Esys_CreatePrimary: %s", Tss2_RC_Decode(ret));
		return FALSE;
	}

	Esys_Free(public);
	Esys_Free(creation_data);
	Esys_Free(hash);
	Esys_Free(ticket);

	return TRUE;
}

static GBytes *
egg_tpm2_generate_random_data(EggTpm2Context *context,
		               GError **error)
{
	TSS2_RC ret;
	TPM2B_DIGEST *random_data;
	GBytes *bytes;

	ret = Esys_GetRandom(context->esys_context, ESYS_TR_NONE,
			     ESYS_TR_NONE, ESYS_TR_NONE, MAX_BYTE_SIZE,
			     &random_data);

	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Esys_GetRandom: %s", Tss2_RC_Decode(ret));
		return NULL;
	}

	bytes = g_bytes_new(random_data->buffer, random_data->size);
	Esys_Free(random_data);

	return bytes;
}

EggTpm2Context *
egg_tpm2_initialize(GError **error)
{
	TSS2_RC ret;
	EggTpm2Context *context;
	gsize n_context;
	const gchar *tcti_conf;
	gboolean status;

	n_context = 1;
	context = g_new(EggTpm2Context, n_context);
	tcti_conf = g_getenv("TCTI");
	ret = Tss2_TctiLdr_Initialize(tcti_conf, &context->tcti_context);

	if (ret != TSS2_RC_SUCCESS) {
		egg_tpm2_finalize(context);
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Tss2_TctiLdr_Initialize: %s",
			    Tss2_RC_Decode(ret));
		return NULL;
	}

	ret = Esys_Initialize(&context->esys_context,
			      context->tcti_context, NULL);
	if (ret != TSS2_RC_SUCCESS) {
		egg_tpm2_finalize(context);
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Esys_Initialize: %s", Tss2_RC_Decode(ret));
		return NULL;
	}

	ret = Esys_Startup(context->esys_context, TPM2_SU_CLEAR);
	if (ret != TSS2_RC_SUCCESS) {
		egg_tpm2_finalize(context);
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Esys_Startup: %s", Tss2_RC_Decode(ret));
		return NULL;
	}

	status = egg_tpm2_generate_primary_key(context, error);
	if (!status) {
		egg_tpm2_finalize(context);
		return NULL;
	}

	return context;
}

void
egg_tpm2_finalize(EggTpm2Context *context)
{
	if (context->esys_context)
		Esys_Finalize(&context->esys_context);

	if (context->tcti_context)
		Tss2_TctiLdr_Finalize(&context->tcti_context);

	g_free(context);
}

GBytes *
egg_tpm2_generate_master_password(EggTpm2Context *context,
		                   GError **error)
{
	TSS2_RC ret;
	TPM2B_PRIVATE *out_private;
	TPM2B_PUBLIC *out_public;
	TPM2B_CREATION_DATA *creation_data;
	TPM2B_DIGEST *hash;
	TPMT_TK_CREATION *ticket;
	gconstpointer data;
	gsize size;
	GBytes *input;
	GBytes *output;

	TPM2B_SENSITIVE_CREATE in_sensitive = {
		.size = 0,
		.sensitive = {
			.data = {
				.size = MAX_BYTE_SIZE
			}
		}
	};

	TPM2B_PUBLIC in_public = {
		.size = 0,
		.publicArea = {
			.type = TPM2_ALG_KEYEDHASH,
			.nameAlg = TPM2_ALG_SHA256,
			.objectAttributes = (
				TPMA_OBJECT_USERWITHAUTH |
				TPMA_OBJECT_FIXEDTPM |
				TPMA_OBJECT_FIXEDPARENT),
			.authPolicy = {
				.size = 0,
			},
			.parameters.keyedHashDetail = {
				.scheme = {
					.scheme = TPM2_ALG_NULL,
					.details = {
						.hmac = {
							.hashAlg =
								TPM2_ALG_SHA256
						}
					}
				}
			},
			.unique.keyedHash = {
				.size = 0,
				.buffer = {},
			},
		}
	};

	TPM2B_DATA outside_info = {
		.size = 0,
		.buffer = {}
	};

	TPML_PCR_SELECTION pcrs = {
		.count = 0
	};

	input = egg_tpm2_generate_random_data(context, error);
	if (!input) {
		g_bytes_unref(input);
		return NULL;
	}

	data = g_bytes_get_data(input, &size);
	if (size > sizeof(in_sensitive.sensitive.data.buffer)) {
		g_set_error_literal(error,
				    G_IO_ERROR,
				    G_IO_ERROR_INVALID_ARGUMENT,
				    "Input is too long");
		return NULL;
	}

	memcpy(in_sensitive.sensitive.data.buffer, data, size);
	in_sensitive.sensitive.data.size = size;
	g_bytes_unref(input);

	ret = Esys_Create(context->esys_context, context->primary_key,
			  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			  &in_sensitive, &in_public, &outside_info,
			  &pcrs, &out_private, &out_public, &creation_data,
			  &hash, &ticket);
	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Esys_Create: %s", Tss2_RC_Decode(ret));
		return NULL;
	}

	gsize out_private_offset = 0;
	gsize out_public_offset = 0;
	GVariant *out_private_variant;
	GVariant *out_public_variant;
	GVariant *variant;

	guint8 marshaled_out_private[sizeof(*out_private)];
	guint8 marshaled_out_public[sizeof(*out_public)];

	ret = Tss2_MU_TPM2B_PRIVATE_Marshal(out_private,
			                    marshaled_out_private,
					    sizeof(marshaled_out_private),
					    &out_private_offset);
	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Tss2_MU_TPM2B_PRIVATE_Marshal: %s",
			    Tss2_RC_Decode(ret));
		return NULL;
	}

	out_private_variant = g_variant_new_fixed_array(
			G_VARIANT_TYPE_BYTE,
			marshaled_out_private,
			out_private_offset,
			sizeof(guint8));

	ret = Tss2_MU_TPM2B_PUBLIC_Marshal(out_public,
			                   marshaled_out_public,
					   sizeof(marshaled_out_public),
					   &out_public_offset);
	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Tss2_MU_TPM2B_PUBLIC_Marshal: %s",
			    Tss2_RC_Decode(ret));
		return NULL;
	}

	out_public_variant = g_variant_new_fixed_array(
			G_VARIANT_TYPE_BYTE,
			marshaled_out_public,
			out_public_offset,
			sizeof(guint8));

	variant = g_variant_new("(u@ayu@ay)",
			        out_private_offset, out_private_variant,
				out_public_offset, out_public_variant);

	output = g_variant_get_data_as_bytes(variant);

	g_variant_unref(variant);
	Esys_Free(out_public);
	Esys_Free(out_private);
	Esys_Free(creation_data);
	Esys_Free(hash);
	Esys_Free(ticket);

	return output;
}

GBytes *
egg_tpm2_decrypt_master_password(EggTpm2Context *context,
		                  GBytes *input,
				  GError **error)
{
	TSS2_RC ret;
	GBytes *output;
	TPM2B_SENSITIVE_DATA *out_data;
	GVariant *variant;
	gconstpointer data;
	gsize out_private_offset = 0;
	gsize out_public_offset = 0;
	gsize count = 0;
	gsize offset = 0;
	GVariant *out_private_variant;
	GVariant *out_public_variant;
	ESYS_TR out_key;

	variant = g_variant_new_from_bytes(G_VARIANT_TYPE(
				           "(uayuay)"),
					   input,
					   TRUE);

	g_variant_get(variant, "(u@ayu@ay)",
		      &out_private_offset, &out_private_variant,
		      &out_public_offset, &out_public_variant);
	g_variant_unref(variant);

	data = g_variant_get_fixed_array(out_private_variant,
					 &count,
			                 sizeof(guint8));
	guint8 *marshaled_out_private = g_memdup2(data, count);
	count = 0;

	TPM2B_PRIVATE out_private = {
		.size = 0
	};
	ret = Tss2_MU_TPM2B_PRIVATE_Unmarshal(marshaled_out_private,
					      out_private_offset,
					      &offset,
					      &out_private);

	g_variant_unref(out_private_variant);
	g_free(marshaled_out_private);

	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Tss2_MU_TPM2B_PRIVATE_Unmarshal: %s",
			    Tss2_RC_Decode(ret));
		return NULL;
	}

	offset = 0;
	data = g_variant_get_fixed_array(out_public_variant,
					 &count,
					 sizeof(guint8));
	guint8 *marshaled_out_public = g_memdup2(data, count);

	TPM2B_PUBLIC out_public = {
		.size = 0
	};
	ret = Tss2_MU_TPM2B_PUBLIC_Unmarshal(marshaled_out_public,
					     out_public_offset,
					     &offset,
					     &out_public);

	g_variant_unref(out_public_variant);
	g_free(marshaled_out_public);

	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Tss2_MU_TPM2B_PUBLIC_Unmarshal: %s",
			    Tss2_RC_Decode(ret));
		return NULL;
	}

	ret = Esys_Load(context->esys_context, context->primary_key,
			ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			&out_private, &out_public, &out_key);
	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Esys_Load: %s", Tss2_RC_Decode(ret));
		return NULL;
	}

	ret = Esys_Unseal(context->esys_context, out_key,
			  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			  &out_data);
	if (ret != TSS2_RC_SUCCESS) {
		g_set_error(error,
			    G_IO_ERROR,
			    G_IO_ERROR_FAILED,
			    "Esys_Unseal: %s", Tss2_RC_Decode(ret));
		return NULL;
	}

	output = g_bytes_new(out_data->buffer, out_data->size);
	Esys_Free(out_data);

	return output;
}
