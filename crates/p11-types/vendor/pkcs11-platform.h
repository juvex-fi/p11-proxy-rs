/* pkcs11/v3.2/pkcs11-platform.h
 * Platform macro definitions required by the OASIS PKCS#11 v3.2 headers
 * on Unix/Linux/macOS before including pkcs11.h.
 */
#ifndef PKCS11_PLATFORM_H
#define PKCS11_PLATFORM_H

#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) \
	returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#endif /* PKCS11_PLATFORM_H */
