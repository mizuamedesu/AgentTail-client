// SPDX-License-Identifier: GPL-3.0-or-later

//go:build darwin && cgo

package secrets

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static OSStatus at_keychain(SecKeychainRef *chain) {
    SecKeychainSetUserInteractionAllowed(false);
    return SecKeychainOpen("/Library/Keychains/System.keychain", chain);
}
static OSStatus at_create(SecKeychainRef chain, const char *account, const void *data, UInt32 length) {
    // The daemon starts before a GUI login. A root-owned ACL permits the
    // verified updater to add a new code identity without a SecurityAgent
    // prompt; the actual credential operations still require our executable.
    CFErrorRef error = NULL;
    SecAccessRef access = SecAccessCreateWithOwnerAndACL(0, 0, kSecUseOnlyUID, NULL, &error);
    if (!access) {
        OSStatus status = error ? (OSStatus)CFErrorGetCode(error) : errSecAllocate;
        if (error) CFRelease(error);
        return status;
    }
    SecTrustedApplicationRef app = NULL; SecACLRef acl = NULL;
    OSStatus status = SecTrustedApplicationCreateFromPath(NULL, &app);
    CFArrayRef apps = NULL, rights = NULL;
    if (!status) {
        const void *values[] = { app };
        apps = CFArrayCreate(NULL, values, 1, &kCFTypeArrayCallBacks);
        status = SecACLCreateWithSimpleContents(access, apps, CFSTR("AgentTail credential"), 0, &acl);
    }
    if (!status) {
        const void *values[] = { kSecACLAuthorizationAny };
        rights = CFArrayCreate(NULL, values, 1, &kCFTypeArrayCallBacks);
        status = SecACLUpdateAuthorizations(acl, rights);
    }
    if (!status) {
        SecKeychainAttribute attrs[] = {
            { kSecServiceItemAttr, 9, (void *)"AgentTail" },
            { kSecAccountItemAttr, (UInt32)strlen(account), (void *)account }
        };
        SecKeychainAttributeList list = { 2, attrs };
        status = SecKeychainItemCreateFromContent(kSecGenericPasswordItemClass, &list, length, data, chain, access, NULL);
    }
    if (rights) CFRelease(rights); if (apps) CFRelease(apps);
    if (acl) CFRelease(acl); if (app) CFRelease(app); CFRelease(access);
    return status;
}
static OSStatus at_put(const char *account, const void *data, UInt32 length) {
    SecKeychainRef chain = NULL; SecKeychainItemRef item = NULL;
    OSStatus status = at_keychain(&chain); if (status) return status;
    status = SecKeychainFindGenericPassword(chain, 9, "AgentTail", (UInt32)strlen(account), account, NULL, NULL, &item);
    if (status == errSecSuccess) status = SecKeychainItemModifyAttributesAndData(item, NULL, length, data);
    else if (status == errSecItemNotFound) status = at_create(chain, account, data, length);
    if (item) CFRelease(item); CFRelease(chain); return status;
}
static OSStatus at_get(const char *account, void **data, UInt32 *length) {
    SecKeychainRef chain = NULL; OSStatus status = at_keychain(&chain); if (status) return status;
    status = SecKeychainFindGenericPassword(chain, 9, "AgentTail", (UInt32)strlen(account), account, length, data, NULL);
    CFRelease(chain); return status;
}
static OSStatus at_delete(const char *account) {
    SecKeychainRef chain = NULL; SecKeychainItemRef item = NULL; OSStatus status = at_keychain(&chain); if (status) return status;
    status = SecKeychainFindGenericPassword(chain, 9, "AgentTail", (UInt32)strlen(account), account, NULL, NULL, &item);
    if (!status) { status = SecKeychainItemDelete(item); CFRelease(item); }
    CFRelease(chain); return status;
}
static OSStatus at_authorize(const char *account, const char *path) {
    SecKeychainRef chain = NULL; SecKeychainItemRef item = NULL;
    SecAccessRef access = NULL; SecTrustedApplicationRef app = NULL; CFArrayRef acls = NULL;
    OSStatus status = at_keychain(&chain); if (status) return status;
    status = SecKeychainFindGenericPassword(chain, 9, "AgentTail", (UInt32)strlen(account), account, NULL, NULL, &item);
    if (status == errSecItemNotFound) { CFRelease(chain); return errSecSuccess; }
    if (!status) status = SecTrustedApplicationCreateFromPath(path, &app);
    if (!status) status = SecKeychainItemCopyAccess(item, &access);
    if (!status) status = SecAccessCopyACLList(access, &acls);
    for (CFIndex i = 0; !status && i < CFArrayGetCount(acls); i++) {
        SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acls, i);
        CFArrayRef rights = SecACLCopyAuthorizations(acl);
        Boolean credentialACL = rights && (
            CFArrayContainsValue(rights, CFRangeMake(0, CFArrayGetCount(rights)), kSecACLAuthorizationAny) ||
            CFArrayContainsValue(rights, CFRangeMake(0, CFArrayGetCount(rights)), kSecACLAuthorizationDecrypt));
        if (rights) CFRelease(rights);
        // Preserve owner, integrity and partition ACLs without interpreting
        // their process/code subjects as a simple application list.
        if (!credentialACL) continue;
        CFArrayRef applications = NULL; CFStringRef description = NULL;
        SecKeychainPromptSelector prompt = 0;
        status = SecACLCopyContents(acl, &applications, &description, &prompt);
        if (status == errSecACLNotSimple) {
            // The root process-subject ACL is intentionally not an app list.
            // Preserve it verbatim; only migrate simple code-identity ACLs.
            status = errSecSuccess;
            if (applications) CFRelease(applications);
            if (description) CFRelease(description);
            continue;
        }
        // NULL is already unrestricted for this operation. Never replace an
        // application-restricted list with NULL or an empty list.
        if (!status && applications) {
            CFMutableArrayRef copy = CFArrayCreateMutableCopy(NULL, 0, applications);
            CFArrayAppendValue(copy, app);
            status = SecACLSetContents(acl, copy, description, prompt);
            CFRelease(copy);
        }
        if (applications) CFRelease(applications);
        if (description) CFRelease(description);
    }
    if (!status) status = SecKeychainItemSetAccess(item, access);
    if (acls) CFRelease(acls); if (app) CFRelease(app);
    if (access) CFRelease(access); if (item) CFRelease(item); CFRelease(chain);
    return status;
}
*/
import "C"
import (
	"fmt"
	"os"
	"unsafe"
)

func DefaultDirectory() string { return "/Library/Application Support/AgentTail" }
func keychainError(status C.OSStatus) error {
	if status == C.errSecItemNotFound {
		return os.ErrNotExist
	}
	return fmt.Errorf("System Keychain operation failed (OSStatus %d); root and a native signed build are required", int(status))
}
func (s *Store) put(credential string, data []byte) error {
	account := C.CString(credential)
	defer C.free(unsafe.Pointer(account))
	buffer := C.CBytes(data)
	defer func() { C.memset(buffer, 0, C.size_t(len(data))); C.free(buffer) }()
	status := C.at_put(account, buffer, C.UInt32(len(data)))
	if status != 0 {
		return keychainError(status)
	}
	return nil
}
func (s *Store) get(credential string) ([]byte, error) {
	account := C.CString(credential)
	defer C.free(unsafe.Pointer(account))
	var data unsafe.Pointer
	var length C.UInt32
	status := C.at_get(account, &data, &length)
	if status != 0 {
		return nil, keychainError(status)
	}
	defer func() { C.memset(data, 0, C.size_t(length)); C.SecKeychainItemFreeContent(nil, data) }()
	return C.GoBytes(data, C.int(length)), nil
}
func (s *Store) remove(credential string) error {
	account := C.CString(credential)
	defer C.free(unsafe.Pointer(account))
	status := C.at_delete(account)
	if status == 0 || status == C.errSecItemNotFound {
		return nil
	}
	return keychainError(status)
}

// The updater first verifies and copies the executable to a root-owned path,
// then permits its code identity while retaining the old one for rollback.
func (s *Store) AuthorizeExecutable(path string, scopes []string) error {
	p := C.CString(path)
	defer C.free(unsafe.Pointer(p))
	for _, scope := range scopes {
		name := C.CString(s.name(scope))
		status := C.at_authorize(name, p)
		C.free(unsafe.Pointer(name))
		if status != 0 {
			return keychainError(status)
		}
	}
	return nil
}
