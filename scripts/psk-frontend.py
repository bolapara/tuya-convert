#!/usr/bin/env python3

# Patched for Python 3.12+ / OpenSSL 3.x.
#
# Upstream used the `sslpsk` C extension (unmaintained since 2019), which no
# longer builds on modern Python.
#
# The obvious replacement -- the TLS-PSK support added to the stdlib `ssl`
# module in Python 3.13 -- does NOT work here: CPython decodes the client's PSK
# identity as UTF-8 before invoking the callback, and if that decode fails it
# silently skips the callback and aborts with PSK_IDENTITY_NOT_FOUND. Tuya
# devices send an identity containing raw binary bytes, so the stdlib path can
# never complete the handshake for them.
#
# So we bind OpenSSL's PSK API directly with ctypes, which hands us the identity
# as raw bytes exactly as sslpsk did.

import ctypes
import ctypes.util
import socket
import select
import sys

try:
	from Cryptodome.Cipher import AES
except ImportError:  # some distributions package pycryptodome as "Crypto"
	from Crypto.Cipher import AES
from hashlib import md5
from binascii import hexlify, unhexlify

IDENTITY_PREFIX = b"BAohbmd6aG91IFR1"

# --- OpenSSL bindings -------------------------------------------------------

def _load_openssl(base, sonames):
	found = ctypes.util.find_library(base)
	for candidate in ([found] if found else []) + sonames:
		try:
			return ctypes.CDLL(candidate)
		except OSError:
			continue
	raise ImportError(
		"could not load lib%s -- is OpenSSL installed?" % base)


# Both OpenSSL 3.x and 1.1 provide the PSK API used below.
_libssl = _load_openssl("ssl", ["libssl.so.3", "libssl.so.1.1", "libssl.so"])
_libcrypto = _load_openssl("crypto", ["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"])

OPENSSL_INIT_LOAD_SSL_STRINGS = 0x00200000
OPENSSL_INIT_LOAD_CRYPTO_STRINGS = 0x00000002
_libssl.OPENSSL_init_ssl.argtypes = [ctypes.c_uint64, ctypes.c_void_p]
_libssl.OPENSSL_init_ssl.restype = ctypes.c_int
_libssl.OPENSSL_init_ssl(
	OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, None)

_libssl.TLS_server_method.restype = ctypes.c_void_p
_libssl.SSL_CTX_new.argtypes = [ctypes.c_void_p]
_libssl.SSL_CTX_new.restype = ctypes.c_void_p
_libssl.SSL_CTX_set_cipher_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_libssl.SSL_CTX_set_cipher_list.restype = ctypes.c_int
_libssl.SSL_CTX_use_psk_identity_hint.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_libssl.SSL_CTX_use_psk_identity_hint.restype = ctypes.c_int
_libssl.SSL_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
_libssl.SSL_CTX_ctrl.restype = ctypes.c_long
_libssl.SSL_new.argtypes = [ctypes.c_void_p]
_libssl.SSL_new.restype = ctypes.c_void_p
_libssl.SSL_set_fd.argtypes = [ctypes.c_void_p, ctypes.c_int]
_libssl.SSL_set_fd.restype = ctypes.c_int
_libssl.SSL_accept.argtypes = [ctypes.c_void_p]
_libssl.SSL_accept.restype = ctypes.c_int
_libssl.SSL_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
_libssl.SSL_read.restype = ctypes.c_int
_libssl.SSL_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
_libssl.SSL_write.restype = ctypes.c_int
_libssl.SSL_pending.argtypes = [ctypes.c_void_p]
_libssl.SSL_pending.restype = ctypes.c_int
_libssl.SSL_shutdown.argtypes = [ctypes.c_void_p]
_libssl.SSL_shutdown.restype = ctypes.c_int
_libssl.SSL_free.argtypes = [ctypes.c_void_p]
_libssl.SSL_free.restype = None
_libssl.SSL_get_version.argtypes = [ctypes.c_void_p]
_libssl.SSL_get_version.restype = ctypes.c_char_p

_libcrypto.ERR_get_error.restype = ctypes.c_ulong
_libcrypto.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

SSL_CTRL_SET_MIN_PROTO_VERSION = 123
SSL_CTRL_SET_MAX_PROTO_VERSION = 124
TLS1_2_VERSION = 0x0303

# unsigned int cb(SSL *ssl, const char *identity,
#                 unsigned char *psk, unsigned int max_psk_len)
PSK_SERVER_CB = ctypes.CFUNCTYPE(
	ctypes.c_uint, ctypes.c_void_p, ctypes.c_char_p,
	ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint)
_libssl.SSL_CTX_set_psk_server_callback.argtypes = [ctypes.c_void_p, PSK_SERVER_CB]
_libssl.SSL_CTX_set_psk_server_callback.restype = None


class PskError(Exception):
	pass


def _ssl_errors():
	out = []
	while True:
		e = _libcrypto.ERR_get_error()
		if e == 0:
			break
		buf = ctypes.create_string_buffer(256)
		_libcrypto.ERR_error_string_n(e, buf, 256)
		out.append(buf.value.decode(errors="replace"))
	return "; ".join(out) or "unknown error"


def listener(host, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind((host, port))
	sock.listen(1)
	return sock

def client(host, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((host, port))
	return sock

def gen_psk(identity, hint):
	print("ID: %s" % hexlify(identity).decode())
	if identity[:1] == b'\x02':
		print("!! This device's PSK ID starts with 02, which means it is running")
		print("!! patched firmware. tuya-convert cannot flash it.")
	identity = identity[1:]
	if identity[:16] != IDENTITY_PREFIX:
		print("Prefix: %s" % identity[:16])
	key = md5(hint[-16:]).digest()
	iv = md5(identity).digest()
	cipher = AES.new(key, AES.MODE_CBC, iv)
	psk = cipher.encrypt(identity[:32])
	print("PSK: %s" % hexlify(psk).decode())
	return psk


class PskTlsSocket():
	"""Minimal socket-like wrapper around an OpenSSL SSL* so the proxy loop
	below can treat it the same way it treated an sslpsk socket."""

	def __init__(self, ssl_ptr, raw_sock):
		self._ssl = ssl_ptr
		self._sock = raw_sock

	def fileno(self):
		return self._sock.fileno()

	def recv(self, bufsize):
		buf = ctypes.create_string_buffer(bufsize)
		n = _libssl.SSL_read(self._ssl, buf, bufsize)
		if n <= 0:
			return b''
		data = buf.raw[:n]
		# Drain anything already decrypted and sitting in OpenSSL's buffer,
		# since select() on the raw fd will not report it as readable.
		while _libssl.SSL_pending(self._ssl) > 0:
			extra = ctypes.create_string_buffer(bufsize)
			m = _libssl.SSL_read(self._ssl, extra, bufsize)
			if m <= 0:
				break
			data += extra.raw[:m]
		return data

	def send(self, data):
		return _libssl.SSL_write(self._ssl, data, len(data))

	def shutdown(self, how):
		try:
			_libssl.SSL_shutdown(self._ssl)
		except Exception:
			pass
		try:
			self._sock.shutdown(how)
		except OSError:
			pass

	def close(self):
		if self._ssl:
			_libssl.SSL_free(self._ssl)
			self._ssl = None
		try:
			self._sock.close()
		except OSError:
			pass


class PskFrontend():
	def __init__(self, listening_host, listening_port, host, port):
		self.listening_port = listening_port
		self.listening_host = listening_host
		self.host = host
		self.port = port

		self.server_sock = listener(listening_host, listening_port)
		self.sessions = []
		self.hint = b'1dHRsc2NjbHltbGx3eWh5' b'0000000000000000'

		ctx = _libssl.SSL_CTX_new(_libssl.TLS_server_method())
		if not ctx:
			raise PskError("SSL_CTX_new failed: %s" % _ssl_errors())
		# @SECLEVEL=0 is required: OpenSSL 3.x rates PSK-AES128-CBC-SHA256
		# below its default security level and would refuse the handshake.
		if _libssl.SSL_CTX_set_cipher_list(ctx, b"PSK-AES128-CBC-SHA256:@SECLEVEL=0") != 1:
			raise PskError("set_cipher_list failed: %s" % _ssl_errors())
		_libssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, None)
		_libssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_2_VERSION, None)
		_libssl.SSL_CTX_use_psk_identity_hint(ctx, self.hint)

		def _cb(ssl_ptr, identity, psk_out, max_psk_len):
			try:
				# identity arrives as raw NUL-terminated bytes -- no decoding,
				# which is the whole reason for the ctypes binding.
				psk = gen_psk(identity or b'', self.hint)
				if len(psk) > max_psk_len:
					print("PSK too long (%d > %d)" % (len(psk), max_psk_len))
					return 0
				ctypes.memmove(psk_out, psk, len(psk))
				sys.stdout.flush()
				return len(psk)
			except Exception as e:
				print("PSK callback error: %r" % (e,))
				sys.stdout.flush()
				return 0

		# Keep a reference; ctypes callbacks are garbage collected otherwise.
		self._cb = PSK_SERVER_CB(_cb)
		_libssl.SSL_CTX_set_psk_server_callback(ctx, self._cb)
		self.ctx = ctx

	def readables(self):
		readables = [self.server_sock]
		for (s1, s2) in self.sessions:
			readables.append(s1)
			readables.append(s2)
		return readables

	def new_client(self, s1):
		ssl_ptr = None
		try:
			ssl_ptr = _libssl.SSL_new(self.ctx)
			if not ssl_ptr:
				raise PskError("SSL_new failed: %s" % _ssl_errors())
			if _libssl.SSL_set_fd(ssl_ptr, s1.fileno()) != 1:
				raise PskError("SSL_set_fd failed: %s" % _ssl_errors())
			if _libssl.SSL_accept(ssl_ptr) != 1:
				raise PskError(_ssl_errors())

			ssl_sock = PskTlsSocket(ssl_ptr, s1)
			ssl_ptr = None  # ownership transferred
			print("handshake OK (%s)" % (_libssl.SSL_get_version(ssl_sock._ssl) or b'?').decode())
			s2 = client(self.host, self.port)
			self.sessions.append((ssl_sock, s2))
		except PskError as e:
			msg = str(e)
			print("could not establish psk socket:", msg)
			if "no shared cipher" in msg or "wrong version number" in msg or "unknown protocol" in msg:
				print("don't panic this is probably just your phone!")
			if ssl_ptr:
				_libssl.SSL_free(ssl_ptr)
			try:
				s1.close()
			except OSError:
				pass
		except Exception as e:
			print(e)
			if ssl_ptr:
				_libssl.SSL_free(ssl_ptr)

	def data_ready_cb(self, s):
		if s == self.server_sock:
			_s, frm = s.accept()
			print("new client on port %d from %s:%d"%(self.listening_port, frm[0], frm[1]))
			self.new_client(_s)

		for (s1, s2) in self.sessions:
			if s == s1 or s == s2:
				c = s1 if s == s2 else s2
				try:
					buf = s.recv(4096)
					if len(buf) > 0:
						c.send(buf)
					else:
						s1.shutdown(socket.SHUT_RDWR)
						s2.shutdown(socket.SHUT_RDWR)
						self.sessions.remove((s1,s2))
				except:
					self.sessions.remove((s1,s2))


def main():
	gateway = '10.42.42.1'
	proxies = [PskFrontend(gateway, 443, gateway, 80), PskFrontend(gateway, 8886, gateway, 1883)]

	print("PSK frontend ready (OpenSSL ctypes backend)")
	sys.stdout.flush()

	while True:
		readables = []
		for p in proxies:
			readables = readables + p.readables()
		r,_,_ =  select.select(readables, [], [])
		for s in r:
			for p in proxies:
				p.data_ready_cb(s)
		sys.stdout.flush()


if __name__ == '__main__':
	main()
