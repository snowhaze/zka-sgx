#!/usr/bin/python3

from base64 import b64decode, b64encode
from tempfile import mkdtemp
from getopt import getopt
from os import mkdir
import shutil
import hashlib
import json
import sys
import subprocess
import binascii
import ssl
import http.client as client
import urllib.parse as urlparse
import ctypes
import re

class ed25519:
	"""adapted from https://ed25519.cr.yp.to/python/ed25519.py:
	- replaced / with // (original was for python2)
	- replaced ''.join with bytes (original was for python2)
	- removed unnecessary ord() and chr() (original was for python2)
	- added some self. and self, (original was a separate module instead of a class)
	- moved all constant initializations to __init__ (original was a separate module instead of a class)
	- moved computations which don't depend on pk to __init__ (for performance)
	- replaced expmod with the builtin pow (for performance)
	- made checkvalid return a bool instead of throwing an exception
	- tweaked indentation (to fit with this file)
	- removed unused functions
	- removed import hashlib"""

	def __init__(self,s,m):
		self.b = 256
		self.q = 2**255 - 19
		self.l = 2**252 + 27742317777372353535851937790883648493
		self.d = -121665 * self.inv(121666)
		self.I = pow(2,(self.q-1)//4,self.q)
		self.By = 4 * self.inv(5)
		self.Bx = self.xrecover(self.By)
		self.B = [self.Bx % self.q,self.By % self.q]

		if len(s) != self.b//4: raise Exception("signature length is wrong")
		self.m = m
		self.R = self.decodepoint(s[0:self.b//8])
		S = self.decodeint(s[self.b//8:self.b//4])
		self.Rpoint = self.encodepoint(self.R)
		self.verifier = self.scalarmult(self.B,S)

	def H(self,m):
		return hashlib.sha512(m).digest()

	def inv(self,x):
		return pow(x,self.q-2,self.q)

	def xrecover(self,y):
		xx = (y*y-1) * self.inv(self.d*y*y+1)
		x = pow(xx,(self.q+3)//8,self.q)
		if (x*x - xx) % self.q != 0: x = (x*self.I) % self.q
		if x % 2 != 0: x = self.q-x
		return x

	def edwards(self,P,Q):
		x1 = P[0]
		y1 = P[1]
		x2 = Q[0]
		y2 = Q[1]
		x3 = (x1*y2+x2*y1) * self.inv(1+self.d*x1*x2*y1*y2)
		y3 = (y1*y2+x1*x2) * self.inv(1-self.d*x1*x2*y1*y2)
		return [x3 % self.q,y3 % self.q]

	def scalarmult(self,P,e):
		if e == 0: return [0,1]
		Q = self.scalarmult(P,e//2)
		Q = self.edwards(Q,Q)
		if e & 1: Q = self.edwards(Q,P)
		return Q

	def encodepoint(self,P):
		x = P[0]
		y = P[1]
		bits = [(y >> i) & 1 for i in range(self.b - 1)] + [x & 1]
		return bytes([sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(self.b//8)])

	def bit(self,h,i):
		return (h[i//8] >> (i%8)) & 1

	def Hint(self,m):
		h = self.H(m)
		return sum(2**i * self.bit(h,i) for i in range(2*self.b))

	def isoncurve(self,P):
		x = P[0]
		y = P[1]
		return (-x*x + y*y - 1 - self.d*x*x*y*y) % self.q == 0

	def decodeint(self,s):
		return sum(2**i * self.bit(s,i) for i in range(0,self.b))

	def decodepoint(self,s):
		y = sum(2**i * self.bit(s,i) for i in range(0,self.b-1))
		x = self.xrecover(y)
		if x & 1 != self.bit(s,self.b-1): x = self.q-x
		P = [x,y]
		if not self.isoncurve(P): raise Exception("decoding point that is not on curve")
		return P

	def checkvalid(self,pk):
		if len(pk) != self.b//8: raise Exception("public-key length is wrong")
		A = self.decodepoint(pk)
		h = self.Hint(self.Rpoint + pk + self.m)
		return self.verifier == self.edwards(self.R,self.scalarmult(A,h))

# declare some constants
RESULT = 0
NOTE = 1
WARNING = 2
ERROR = 3
FATAL = 4

APPLE_COMPAT = "apple-compat"

# formats & colors outputed messages
def output(severity, message):
	if severity == RESULT:
		prefix = "RESULT"
		color = "32"
	elif severity == NOTE:
		prefix = "NOTE"
		color = "90"
	elif severity == WARNING:
		prefix = "WARNING"
		color = "33"
	elif severity == ERROR:
		prefix = "ERROR"
		color = "31"
	elif severity == FATAL:
		prefix = "FATAL"
		color = "31"
	else:
		prefix = "UNEXPECTED"
		color = "34"

	preflen = len(prefix)

	if sys.stdout.isatty():
		prefix = "\x1b[" + color + "m" + prefix
		suffix = "\x1b[0m"
	else:
		suffix = ""

	lines = message.split("\n")
	if len(lines) == 1:
		print(prefix + ":" + (" " * (8 - preflen)) + message + suffix)
	else:
		print(prefix + ":\n  " + "\n  ".join(lines) + suffix)

# setup everything necessary to bail out cleanly if something goes wrong
tempdir = mkdtemp()
def fail(m):
	shutil.rmtree(tempdir, ignore_errors=True)
	output(FATAL, m)
	sys.exit(1)

# check for sufficiently recent python versions
if sys.version_info.major < 3 or (sys.version_info.major == 3 and sys.version_info.minor < 6):
	fail(f"""Unsupported Python Version:
Running: {sys.version}
Required: >= 3.6""")

# parse & validate cli arguments
crypto_path = "openssl"
cache_files = None
no_network = False
revocation_check = False
limit = None
add_certs = False
build_files_directory = None
try:
	options = getopt(sys.argv[1:], "o:c:l:b:rhvna", ["openssl=", "cache=", "help", "version", "revocation-checks", "no-network", "limit=", "add-tls-certs", "build-files="])
except Exception:
	fail("Incorrect Usage - See `" + sys.argv[0] + " --help` for help")
except:
	fail("Failed to Parse Arguments")
for option in options[0]:
	if option[0] == "-o" or option[0] == "--openssl":
		crypto_path = option[1]
	elif option[0] == "-a" or option[0] == "--add-tls-certs":
		add_certs = True
	elif option[0] == "-c" or option[0] == "--cache":
		cache_files = option[1]
	elif option[0] == "-n" or option[0] == "--no-network":
		no_network = True
	elif option[0] == "-l" or option[0] == "--limit":
		try:
			limit = int(option[1])
		except Exception:
			fail("Incorrect Usage - See `" + sys.argv[0] + " --help` for help")
	elif option[0] == "-h" or option[0] == "--help":
		print("Usage: " + sys.argv[0] + " [options] <verification blob>")
		print("""Options:
-h, --help                Display this help message and exit. The verification
                          blob does not have to be specified with this option.

-v, --version             Display the version of the verification script and
                          exit. The verification blob does not have to be
                          specified with this option.

-o, --openssl <cmd>       The command used to run the `openssl` cli. LibreSSL's
                          openssl compatible cli does not work. Since LibreSSL
                          is the default on most macOS installations, macOS
                          users will have to install openssl or use
                          'apple-compat'. The special value 'apple-compat' can
                          be used on Apple platforms (iOS, macOS) to run this
                          verification without a the need for a separate OpenSSL
                          installation.

-a, --add-tls-certs       Add the last known certificates of the respective
                          sites to the list of trusted certificates. This allows
                          the verification to complete on systems with outdated
                          CA lists.

-c, --cache <path>        The path to the cache directory. This has several
                          advantages:
                          - It can speed up the verification on slow networks.
                          - It allows for offline reverification of previously
                              verified verification blobs.
                          - Cached files can be exchanged between multiple
                              users, allowing them to verify that the server
                              does indeed serve static responses.

-n, --no-network          Do not initiate any network connection. If a required
                          file is not in the cache directory, the verification
                          will fail. Can only be used in combination with
                          --cache.

-l, --limit <int>         When searching for matching public keys, only consider
                          the most recent <int> runs.

-r, --revocation-checks   Verify that the certificate used by the API server has
                          not been revoked.

-b, --build-files <path>  The directory into which files required to reproduce
                          the enclave build should be written.""")
		sys.exit(0)
	elif option[0] == "-v" or option[0] == "--version":
		print("ZKA Attestation Verification Tool Version 1.0")
		sys.exit(0)
	elif option[0] == "-r" or option[0] == "--revocation-checks":
		revocation_check = True
	elif option[0] == "-b" or option[0] == "--build-files":
		build_files_directory = option[1]
	else:
		fail("Incorrect Usage - See `" + sys.argv[0] + " --help` for help")
if len(options[1]) != 1 or (no_network and cache_files == None):
	fail("Incorrect Usage - See `" + sys.argv[0] + " --help` for help")
try:
	verification_blob = b64decode(options[1][0], validate=True)
except Exception:
	fail("Incorrect Usage - See `" + sys.argv[0] + " --help` for help")
except:
	fail("Failed to Parse Arguments")

if verification_blob[0] != 1:
	fail("Unsupported Verification Blob Version")
verification_blob = verification_blob[1:]
if len(verification_blob) < 64:
	fail("Invalid Verification Blob")

# setup SSLContext used for downloading files
sslContext = ssl.create_default_context()
sslContext.options = ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE | ssl.OP_NO_COMPRESSION
sslContext.verify_flags = ssl.VERIFY_X509_STRICT | ssl.VERIFY_X509_TRUSTED_FIRST
if hasattr(sslContext, "minimum_version"):
	sslContext.minimum_version = ssl.TLSVersion.TLSv1_2
else:
	sslContext.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

if add_certs:
	sslContext.load_verify_locations(cadata="""-----BEGIN CERTIFICATE-----
MIIF3jCCA8agAwIBAgIQAf1tMPyjylGoG7xkDjUDLTANBgkqhkiG9w0BAQwFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0pl
cnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNV
BAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAw
MjAxMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVU
aGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2Vy
dGlmaWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCAEmUXNg7D2wiz0KxXDXbtzSfTTK1Qg2HiqiBNCS1kCdzOiZ/MPans9s/B
3PHTsdZ7NygRK0faOca8Ohm0X6a9fZ2jY0K2dvKpOyuR+OJv0OwWIJAJPuLodMkY
tJHUYmTbf6MG8YgYapAiPLz+E/CHFHv25B+O1ORRxhFnRghRy4YUVD+8M/5+bJz/
Fp0YvVGONaanZshyZ9shZrHUm3gDwFA66Mzw3LyeTP6vBZY1H1dat//O+T23LLb2
VN3I5xI6Ta5MirdcmrS3ID3KfyI0rn47aGYBROcBTkZTmzNg95S+UzeQc0PzMsNT
79uq/nROacdrjGCT3sTHDN/hMq7MkztReJVni+49Vv4M0GkPGw/zJSZrM233bkf6
c0Plfg6lZrEpfDKEY1WJxA3Bk1QwGROs0303p+tdOmw1XNtB1xLaqUkL39iAigmT
Yo61Zs8liM2EuLE/pDkP2QKe6xJMlXzzawWpXhaDzLhn4ugTncxbgtNMs+1b/97l
c6wjOy0AvzVVdAlJ2ElYGn+SNuZRkg7zJn0cTRe8yexDJtC/QV9AqURE9JnnV4ee
UB9XVKg+/XRjL7FQZQnmWEIuQxpMtPAlR1n6BB6T1CZGSlCBst6+eLf8ZxXhyVeE
Hg9j1uliutZfVS7qXMYoCAQlObgOK6nyTJccBz8NUvXt7y+CDwIDAQABo0IwQDAd
BgNVHQ4EFgQUU3m/WqorSs9UgOHYm8Cd8rIDZsswDgYDVR0PAQH/BAQDAgEGMA8G
A1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAFzUfA3P9wF9QZllDHPF
Up/L+M+ZBn8b2kMVn54CVVeWFPFSPCeHlCjtHzoBN6J2/FNQwISbxmtOuowhT6KO
VWKR82kV2LyI48SqC/3vqOlLVSoGIG1VeCkZ7l8wXEskEVX/JJpuXior7gtNn3/3
ATiUFJVDBwn7YKnuHKsSjKCaXqeYalltiz8I+8jRRa8YFWSQEg9zKC7F4iRO/Fjs
8PRF/iKz6y+O0tlFYQXBl2+odnKPi4w2r78NBc5xjeambx9spnFixdjQg3IM8WcR
iQycE0xyNN+81XHfqnHd4blsjDwSXWXavVcStkNr/+XeTWYRUc+ZruwXtuhxkYze
Sf7dNXGiFSeUHM9h4ya7b6NnJSFd5t0dCy5oGzuCr+yDZ4XUmFF0sbmZgIn/f3gZ
XHlKYC6SQK5MNyosycdiyA5d9zZbyuAlJQG03RoHnHcAP9Dc1ew91Pq7P8yF1m9/
qS3fuQL39ZeatTXaw2ewh0qpKJ4jjv9cJ2vhsE/zB+4ALtRZh8tSQZXq9EfX7mRB
VXyNWQKV3WKdwrnuWih0hKWbt5DHDAff9Yk2dDLWKMGwsAvgnEzDHNb842m1R0aB
L6KCq9NjRHDEjf8tM7qtj3u1cIiuPhnPQCjY/MiQu12ZIvVS5ljFH4gxQ+6IHdfG
jjxDah2nGN59PRbxYvnKkKj9
-----END CERTIFICATE-----
""")

if revocation_check:
	sslContext.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

# run openssl cli with the specified arguments and return stdout as str
def openssl(args):
	try:
		result = subprocess.run([crypto_path] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
	except:
		fail("Failed to Run OpenSSL")
	try:
		return result.stdout.decode()
	except:
		fail("Failed to Decode OpenSSL Output")

# returns the used openssl version of
def crypto_version():
	if crypto_path == APPLE_COMPAT:
		return "Security.framework"
	else:
		return openssl(["version"])

# load & configure the Security.framework if required by 'apple-compat'
def security_framework():
	try:
		sec = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/Security.framework/Security")

		# set argtypes
		sec.CFRelease.argtypes = [ctypes.c_void_p]
		sec.CFDataCreate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_long]
		sec.SecCertificateCreateWithData.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
		sec.SecCertificateCopyKey.argtypes = [ctypes.c_void_p]
		sec.SecKeyCopyExternalRepresentation.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
		sec.CFDataGetLength.argtypes = [ctypes.c_void_p]
		sec.CFDataGetBytes.argtypes = [ctypes.c_void_p, CFRange, ctypes.c_char_p]
		sec.CFArrayCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_long, ctypes.c_void_p]
		sec.SecPolicyCreateBasicX509.argtypes = []
		sec.SecTrustCreateWithCertificates.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
		sec.SecTrustGetCertificateAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long]
		sec.SecTrustSetAnchorCertificates.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
		sec.SecTrustSetAnchorCertificatesOnly.argtypes = [ctypes.c_void_p, ctypes.c_bool]
		sec.SecTrustEvaluateWithError.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
		sec.SecKeyVerifySignature.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

		# set restype
		sec.CFRelease.restype = None
		sec.CFDataCreate.restype = ctypes.c_void_p
		sec.SecCertificateCreateWithData.restype = ctypes.c_void_p
		sec.SecCertificateCopyKey.restype = ctypes.c_void_p
		sec.SecKeyCopyExternalRepresentation.restype = ctypes.c_void_p
		sec.CFDataGetLength.restype = ctypes.c_long
		sec.CFDataGetBytes.restype = None
		sec.CFArrayCreate.restype = ctypes.c_void_p
		sec.SecPolicyCreateBasicX509.restype = ctypes.c_void_p
		sec.SecTrustCreateWithCertificates.restype = ctypes.c_int
		sec.SecTrustGetCertificateAtIndex.restype = ctypes.c_void_p
		sec.SecTrustSetAnchorCertificates.restype = ctypes.c_int
		sec.SecTrustSetAnchorCertificatesOnly.restype = ctypes.c_int
		sec.SecTrustEvaluateWithError.restype = ctypes.c_bool
		sec.SecKeyVerifySignature.restype = ctypes.c_bool

		return sec
	except:
		fail("Failed to Load Security.framework")

# required for crypto using 'apple-compat'
class CFRange (ctypes.Structure):
	_fields_ = [("location", ctypes.c_long), ("length", ctypes.c_long)]
	def __init__(self, location, length):
		self.location = location
		self.length = length

# abort rather than segfault if a null pointer slipped in somewhere
def check_not_null(ptr):
	if ptr == None:
		fail("Unexpected Error")

# create a SecCertificate as required for crypto using 'apple-compat'
def make_certs(pem, sec):
	# split PEM into separate DER encoded certificate
	ders = [b64decode(x) for x in re.split(b"-+(?:BEGIN|END) CERTIFICATE-+\n?", pem) if len(x)]
	CertsArray = ctypes.c_void_p * len(ders)
	certs = CertsArray()
	
	# create SecCertRefs from the DERs
	for i, der in enumerate(ders):
		data = sec.CFDataCreate(None, der, ctypes.c_long(len(der)))
		check_not_null(data)
		cert = sec.SecCertificateCreateWithData(None, data)
		if cert == None:
			fail("Failed to Parse Certificate Chain")
		sec.CFRelease(data)
		certs[i] = cert

	# create a CFArrayRef with these certificates
	certs_pointer = ctypes.cast(ctypes.pointer(certs), ctypes.POINTER(ctypes.c_void_p))
	callbacks = ctypes.cast(sec.kCFTypeArrayCallBacks, ctypes.c_void_p)
	array = sec.CFArrayCreate(None, certs_pointer, len(ders), callbacks)
	for cert in certs:
		sec.CFRelease(cert)
	check_not_null(array)
	return array

# create a SecTrust as required for crypto using 'apple-compat'
def make_trust(chain, sec):
	certs = make_certs(chain, sec)
	policy = sec.SecPolicyCreateBasicX509()
	check_not_null(policy)
	trust = ctypes.c_void_p()
	success = sec.SecTrustCreateWithCertificates(certs, policy, ctypes.pointer(trust))
	sec.CFRelease(policy)
	if success != 0:
		fail("Failed to Create Trust Object")
	return trust

# extract the public key from a certificate
def crypto_get_pubkey(chain):
	if crypto_path == APPLE_COMPAT:
		# create the required objects
		sec = security_framework()
		trust = make_trust(chain, sec)

		# get the leaf certificate from the chain
		cert = sec.SecTrustGetCertificateAtIndex(trust, 0)
		sec.CFRelease(trust)
		check_not_null(cert)

		# extract the key from the certificate
		key = sec.SecCertificateCopyKey(cert)
		check_not_null(key)
		sec.CFRelease(cert)
		return key
	else:
		write(tempdir + "/chain", chain)
		return openssl(["x509", "-in", tempdir + "/chain", "-noout", "-pubkey"]).encode()

# check if the output matches the expected value modulo line endings
def shell_check(output, expected):
	def normalize(data):
		return data.replace("\r\n", "\n")
	return normalize(output) == normalize(expected) + "\n"

# check if the certificate chain is rooted by the ca
def crypto_verify_chain(ca_path, chain):
	if crypto_path == APPLE_COMPAT:
		# create the required objects
		sec = security_framework()
		trust = make_trust(chain, sec)
		ca = make_certs(read(ca_path), sec)

		# only trust the Intel Attestation CA
		if sec.SecTrustSetAnchorCertificates(trust, ca) != 0:
			fail("Unexpected Error")
		sec.CFRelease(ca)
		if sec.SecTrustSetAnchorCertificatesOnly(trust, True) != 0:
			fail("Unexpected Error")

		# verify the certificate chain
		result = sec.SecTrustEvaluateWithError(trust, None)
		sec.CFRelease(trust)
		return result
	else:
		chain_path = tempdir + "/chain"
		write(chain_path, chain)
		return shell_check(openssl(["verify", "-purpose", "any", "-x509_strict", "-CAfile", ca_path, chain_path]), chain_path + ": OK")

# check if the signature matches the file and is signed by the key
def crypto_verify_signature(sig, key, data):
	if crypto_path == APPLE_COMPAT:
		# create the required objects
		sec = security_framework()
		sig = sec.CFDataCreate(None, sig, ctypes.c_long(len(sig)))
		check_not_null(sig)
		data = sec.CFDataCreate(None, data, ctypes.c_long(len(data)))
		check_not_null(data)
		algorithm = ctypes.c_void_p.in_dll(sec, "kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256")
		
		# verify the signature
		result = sec.SecKeyVerifySignature(key, algorithm, data, sig, None)
		sec.CFRelease(sig)
		sec.CFRelease(data)
		sec.CFRelease(key)
		return result
	else:
		key_path = tempdir + "/key"
		sig_path = tempdir + "/sig"
		report_path = tempdir + "/report"
		write(key_path, key)
		write(sig_path, sig)
		write(report_path, data)
		return shell_check(openssl(["dgst", "-signature", sig_path, "-verify", key_path, "-sha256", report_path]), "Verified OK")

# return the contents of a file
def read(file):
	fd = open(file, "rb")
	data = fd.read()
	fd.close()
	return data

# write data to a file
def write(file, data):
	fd = open(file, "wb")
	data = fd.write(data)
	fd.close()

if "LibreSSL" in crypto_version():
	fail("LibreSSL Rejects Intel's Attestation CA and Therefore Cannot be Used to Validate the Attestation. See " + sys.argv[0] + " --help for help.")

# download contents of url to file
def download(url, file):
	components = urlparse.urlparse(url)
	assert components.scheme == "https"
	connection = client.HTTPSConnection(components.netloc, context=sslContext)
	try:
		connection.request("GET", url)
		response = connection.getresponse()
		if response.status != 200:
			return False
		write(file, response.read())
		return True
	except Exception:
		return False
	except:
		fail("Failed to Download File")

# ensures file from url is at temp, updating cache if necessary
def get_file(url, cache, temp, name, try_update):
	has_file = False

	# use cached version if it is sufficient
	if (not try_update or no_network) and cache_files != None:
		try:
			shutil.copy(cache_files + "/" + cache, temp)
			return True
		except Exception:
			pass
		except:
			fail("Failed to Copy " + name)
	
	# no cached version could be used
	if no_network:
		fail(name + " is not in the Cache and Networking is Disabled")
	
	# download current file version
	if download(url, temp):
		# cache the newly downloaded file
		if cache_files != None:
			try:
				shutil.copy(temp, cache_files + "/" + cache)
			except:
				fail("Failed to Copy " + name + " into Cache")
	else:
		# fall back to the cached version of the file if available
		if cache_files != None:
			try:
				shutil.copy(cache_files + "/" + cache, temp)
				output(NOTE, "Failed to Download " + name + " - Using Cached Version")
				return
			except:
				pass
		fail(name + " is not Cached and Download Failed")

# create cache directory
if cache_files != None:
	try:
		mkdir(cache_files)
	except FileExistsError:
		pass
	except:
		fail("Failed to Create Cache Directory " + cache_files)

# get the list of all enclave runs
api_url = "https://api.snowhaze.com/attestation"
get_file(api_url + "/index.json", "index.json", tempdir + "/index.json", "Enclave Index File", True)
try:
	index_json = json.loads(read(tempdir + "/index.json"))
except:
	fail("Failed to Parse Enclave Index File")

# parse the list of all enclave runs
if type(index_json) != dict or "version" not in index_json or index_json["version"] != 1:
	fail("Unsupported Enclave Index Version")
if "runs" not in index_json or type(index_json["runs"]) != list or len(index_json["runs"]) == 0:
	fail("Failed to Validate Enclave Index File")
all_keys = index_json["runs"]

# search for matching public key
key_hash = None
try:
	ed25519sig = ed25519(verification_blob[:64], verification_blob[64:])
except Exception:
	fail("Invalid Verification Blob")
	
for k in all_keys[:limit]:
	# validate keys
	try:
		k = b64decode(k, validate=True)
	except binascii.Error:
		output(NOTE, "Ignoring Invalid Keys Structure")
		continue
	except:
		fail("Failed to Decode Keys")
	if len(k) != 96:
		output(NOTE, "Ignoring Unsupported Keys Structure")
		continue
	version = int.from_bytes(k[:4], byteorder="little")
	if version != 1:
		output(NOTE, "Ignoring Unsupported Keys Structure")
		continue

	# check if one of them has signed the verification blob
	try:
		primary_sig = ed25519sig.checkvalid(k[32:32+32])
		seccondary_sig = ed25519sig.checkvalid(k[64:64+32])
	except Exception:
		fail("Invalid Signature or Public Key")
	except:
		fail("Failed to Validate Signature")

	# if one of the keys has signed the verification blob, display the corresponding enclave settings and stop the search
	if primary_sig != seccondary_sig:
		key_hash = bytes([1]) + hashlib.blake2b(k, digest_size = 63).digest()
		output(RESULT, "Verification Blob Signed with " + ("Primary" if primary_sig else "Seccondary") + " Signature Key")
		reserve = int.from_bytes(k[4:4+4], byteorder="little")
		pks = int.from_bytes(k[8:8+4], byteorder="little")
		tokens_per_set = int.from_bytes(k[12:12+4], byteorder="little")
		numerator = int.from_bytes(k[16:16+4], byteorder="little")
		denominator = int.from_bytes(k[20:20+4], byteorder="little")
		output_type = int.from_bytes(k[24:24+8], byteorder="little")
		if denominator == 0:
			fail("Oversize Denominator is Zero")
		output(RESULT, "Enclave Config: " + str(pks) + " Public Keys, " + str(reserve) + " Reserve Sets, " + str(tokens_per_set) + " Tokens Each, " + str(numerator / denominator) + "x Oversized")
		types = []
		if output_type == 0:
			types.append("raw tokens")
		if output_type & 1:
			types.append("hashes")
		if output_type >= 2:
			types.append("unknown")
			output(WARNING, "Unknown Output Type")
		output(RESULT, "Output Types:\n- " + "\n- ".join(types))
		break

# if the public key which signed the verification blob was not found, bail out
if key_hash == None:
	fail("Failed to Find Matching Public Key for Verification Signature")

# get the attestation report for the enclave run which generated the verification blob
report_file = key_hash.hex() + ".json"
get_file(api_url + "/report/" + report_file, "report-" + report_file, tempdir + "/report.json", "Attestation Report", False)

# validate the attestation report
try:
	full_report_json = json.loads(read(tempdir + "/report.json"))
except:
	fail("Failed to Parse Attestation Report")

if type(full_report_json) != dict or "version" not in full_report_json or full_report_json["version"] != 1:
	fail("Unsupported Attestation Report Version")

if "certificate-chain" not in full_report_json or "signature" not in full_report_json or "report" not in full_report_json:
	fail("Failed to Validate Attestation Report")

try:
	chain = full_report_json["certificate-chain"]
	signature = full_report_json["signature"]
	report_body = b64decode(full_report_json["report"], validate=True)
	report = json.loads(report_body)
	status = report["isvEnclaveQuoteStatus"]
	quote = b64decode(report["isvEnclaveQuoteBody"], validate=True)
	advisories = report["advisoryIDs"] if "advisoryIDs" in report else None
	advisoryURL = report["advisoryURL"] if "advisoryURL" in report else None
except:
	fail("Failed to Validate Attestation Report")

if type(signature) != str or type(chain) != str:
	fail("Failed to Validate Attestation Report")

if not "version" in report or report["version"] != 4:
	fail("Unsupported Report Data Version")

# validate the attestation quote
if len(quote) != 432:
	fail("Failed to Validate Attestation Quote")

if quote[1] != 0 and (quote[0] != 1 and quote[0] != 2):
	fail("Unsupported Quote Version")

# ensure attestation report matches the key
if quote[368:(368+64)] != key_hash:
	fail("Key Hash Does not Match")

# download the version information of the tool chain used for the enclave run which generated the report
enclave = quote[112:(112+32)].hex()
enclave_file = enclave + ".json"
get_file(api_url + "/tooling/" + enclave_file, "tooling-" + enclave_file, tempdir + "/versions.json", "Version File", False)

# validate enclave state
attributes = quote[96:(96+16)]
for byte in attributes[1:8] + attributes[9:]:
	if byte:
		fail("Unsupported Enclave Configuration")
if (attributes[0] & ~2) != 5 or attributes[8] != 7:
	fail("Unsupported Enclave Configuration")
if attributes[0] & 2:
	output(ERROR, "Enclave in Debug Mode")

# validate report status & display any reported issues
show_advisories = False
if status == "OK":
	pass
elif status == "SIGNATURE_INVALID":
	output(ERROR, "Invalid Quote Signature")
elif status == "GROUP_REVOKED":
	output(ERROR, "EPID Group Revoked")
	if "revocationReason" in report:
		if type(report["revocationReason"]) == int:
			reason = report["revocationReason"]
			if reason == 0:
				output(NOTE, "Revocation Reason: Unused")
			elif reason == 1:
				output(NOTE, "Revocation Reason: Key Compromise")
			elif reason == 2:
				output(NOTE, "Revocation Reason: CA Compromise")
			elif reason == 3:
				output(NOTE, "Revocation Reason: Affiliation Changed")
			elif reason == 4:
				output(NOTE, "Revocation Reason: Superseeded")
			elif reason == 5:
				output(NOTE, "Revocation Reason: Cessation of Operation")
			elif reason == 6:
				output(NOTE, "Revocation Reason: Certificate Hold")
			elif reason == 8:
				output(NOTE, "Revocation Reason: Remove From CRL")
			elif reason == 9:
				output(NOTE, "Revocation Reason: Privilege Withdrawn")
			elif reason == 10:
				output(NOTE, "Revocation Reason: AA Compromise")
			else:
				output(WARNING, "Invalid Revocation Reason")
		else:
			output(WARNING, "Invalid Revocation Reason")
elif status == "SIGNATURE_REVOKED":
	output(ERROR, "Quote Signature Revoked")
elif status == "KEY_REVOKED":
	output(ERROR, "Key Revoked")
elif status == "SIGRL_VERSION_MISMATCH":
	output(WARNING, "Outdated Revokation List on Server")
elif status == "GROUP_OUT_OF_DATE":
	output(WARNING, "Server out of Date")
	show_advisories = True
elif status == "CONFIGURATION_NEEDED":
	output(WARNING, "Server may Require Configuration")
	show_advisories = True
elif status == "SW_HARDENING_NEEDED":
	output(WARNING, "Enclave may Require Hardening")
	show_advisories = True
elif status == "CONFIGURATION_AND_SW_HARDENING_NEEDED":
	output(WARNING, "Server may Require Configuration and Enclave may Require Hardening")
	show_advisories = True
else:
	fail("Unsupported Status")

if show_advisories and advisories and len(advisories) and advisoryURL:
	output(NOTE, "For more, see\n- " + "\n- ".join(advisories) + "\nat " + advisoryURL)

# obtain SGX attestation root CA
ca_path = tempdir + "/ca"
get_file("https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem", "sgx-attestation-root-ca.pem", ca_path, "SGX Attestation Root CA", False)

# verify attestation report signature
chain = chain.encode()
signature = b64decode(signature, validate=True)
key = crypto_get_pubkey(chain)
if not crypto_verify_chain(ca_path, chain):
	fail("Failed to Verify Certificate Chain")
if not crypto_verify_signature(signature, key, report_body):
	fail("Failed to Verify Attestation Response Signature")

# all went well
output(RESULT, "Verified Chain for Enclave " + enclave)

# parse version file
try:
	version_json = json.loads(read(tempdir + "/versions.json"))
except:
	fail("Failed to Parse Version File")

# cleanup, now that the temp files are no longer needed
shutil.rmtree(tempdir)

# check versions of involved software
if type(version_json) != dict or "version" not in version_json or version_json["version"] != 1:
	fail("Unsupported Version File")
if "tooling" not in version_json or type(version_json["tooling"]) != list:
	fail("Invalid Version File")
all_versions = version_json["tooling"]
if not all(map(lambda x: type(x) == dict, all_versions)) or len(all_versions) == 0:
	fail("Invalid Version File")

# diplay version information of tools used to generate the report
if len(all_versions) > 1:
	output(NOTE, "Found " + str(len(all_versions)) + " Tooling Versions Matching this Enclave Version")
	
if build_files_directory != None:
	try:
		mkdir(build_files_directory)
	except FileExistsError:
		pass
	except:
		fail("Failed to Create Build Files Directory " + build_files_directory)

for versions in all_versions:
	if not all(map(lambda x: type(x) == str and type(versions[x]) == str, versions)):
		fail("Unsupported Version File Format")
	lines = ["Tool Versions:"]
	for name in versions:
		data = versions[name]
		if "." in name and " " not in name and name.islower() and "/" not in name and ".." not in name:
			try:
				data = b64decode(data, validate=True)
			except Exception:
				fail("Unsupported Version File Format" + e)
			if build_files_directory != None:
				write(build_files_directory + "/" + name, data)
				output(NOTE, "Build File " + name + " Created")
			data = hashlib.sha256(data).hexdigest()
		lines.append(name + ": " + data)
	output(NOTE, "\n- ".join(lines))