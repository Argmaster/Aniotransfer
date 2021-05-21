import logging
import pickle as serial
import re
import socket as so
import struct
import sys
import time
import zlib
from io import BytesIO
from math import inf
from typing import Any, Dict, List, Tuple, Union

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

LOG = logging.getLogger("NetIO")
HANDLER = logging.StreamHandler(sys.stderr)
FORMATTER = logging.Formatter("[%(asctime)s] <%(levelname)s> %(message)s")
HANDLER.setFormatter(FORMATTER)
LOG.addHandler(HANDLER)


SSIZE_T = ">Q"
SIZEOF_SSIZE_T = 8
SERIAL_PROTOCOL = 4

_B_DICT = {
    (1, 1024): "B",
    (1024, 1024 ** 2): "KB",
    (1024 ** 2, 1024 ** 3): "MB",
    (1024 ** 3, 1024 ** 4): "GB",
    (1024 ** 4, inf): "TB",
}


def pretty_byecount(val: float) -> str:
    for range, unit in _B_DICT.items():
        if range[0] <= val <= range[1]:
            return f"{val/range[0]:.3f} {unit}"


class Metadata:

    __map__: Dict[str, Any]

    def __init__(self, mapping: Dict[str, Any] = None) -> None:
        """Message metadata header block

        Args:
            mapping (Dict[str, Any], optional): metadata. Defaults to None.

        Raises:
            RuntimeError: supports only dict
        """
        self.__map__ = {}
        if mapping is not None:
            if not isinstance(mapping, dict):
                raise RuntimeError(
                    f"Failed to construct Metadata object out of non-dict type: {type(mapping)}\n  --> {mapping}"
                )
            self.__map__.update(mapping)

    def __str__(self) -> str:
        """Stringify Metadata class

        Returns:
            str: string representation of Metadata class

        >>> Metadata({"meta": 11})
        Metadata<{'meta': 11}>
        """
        string = str(self.__map__)
        string = string if len(string) < 13 else string[:12] + "..."
        return f"Metadata<{string}>"

    __repr__ = __str__

    def __getitem__(self, key: str) -> Any:
        """Access __map__ contents via instance[key] syntax

        Args:
            key (str): key to __map__ dictionary

        Returns:
            Any: value coresponding to key

        >>> Metadata({"foo": "bar"})["foo"]
        'bar'
        """
        LOG.debug(
            f"Access to property Metadata object `{key}`: `{self.__map__.get(key, 'NON-EX')}`"
        )
        return self.__map__[key]

    def __getattr__(self, key: str) -> Any:
        """Access __map__ contents via instance.key syntax

        Args:
            key (str): key to __map__ dictionary

        Returns:
            Any: value coresponding to key

        >>> Metadata({"foo": "bar"}).foo
        'bar'
        """
        str_val = str(self.__dict__["__map__"].get(key, "NON-EX"))
        str_val = str_val if len(str_val) < 20 else str_val[:20] + "..."
        LOG.debug(f"Access to property Metadata object `{key}`: `{str_val}`")
        return self.__map__[key]

    def toBytes(self) -> bytes:
        """Convert object to bytes representation (serialize)

        Returns:
            bytes: serialzied Metadata object

        >>> Metadata({"meta": 11}).toBytes()
        b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x18\\x80\\x04\\x95\\r\\x00\\x00\\x00\\x00\\x00\\x00\\x00}\\x94\\x8c\\x04meta\\x94K\\x0bs.'
        """
        binary = serial.dumps(self.__map__, protocol=SERIAL_PROTOCOL)
        return struct.pack(SSIZE_T, len(binary)) + binary

    @staticmethod
    def fromBytesIO(source: BytesIO) -> "Metadata":
        """Load object from readable source

        Returns:
            Metadata: deserialized metadata object

        >>> io = BytesIO(b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x18\\x80\\x04\\x95\\r\\x00\\x00\\x00\\x00\\x00\\x00\\x00}\\x94\\x8c\\x04meta\\x94K\\x0bs.'); Metadata.fromBytesIO(io)
        Metadata<{'meta': 11}>
        """
        obj = Metadata(
            serial.loads(
                source.read(
                    struct.unpack(
                        SSIZE_T,
                        source.read(SIZEOF_SSIZE_T),
                    )[0],
                )
            )
        )
        LOG.debug(f"Deserialized Metadata object`{obj}`")
        return obj

    @staticmethod
    def fromKwargs(**source) -> "Metadata":
        """Construct Metadata object from keyword arguments

        Returns:
            Metadata: newly constructed Metadata object

        >>> Metadata.fromKwargs(key="KEY", foo=123)
        Metadata<{'key': 'KEY...>
        """
        return Metadata(source)


class Payload:

    __data__: bytes

    def __init__(self, payload: Union[str, bytes] = None) -> None:
        """Stringify Payload class

        Returns:
            str: string representation of Payload class

        >>> Payload(b"Foo bar tar rar")
        Payload<b'Foo bar ta...>
        """
        if payload is not None:
            self.__data__ = (
                payload if isinstance(payload, bytes) else str(payload).encode("utf-8")
            )
        else:
            self.__data__ = b""

    def __str__(self) -> str:
        """Stringify Payload class

        Returns:
            str: string representation of Payload class

        >>> Payload(b"Foo bar tar rar")
        Payload<b'Foo bar ta...>
        """
        string = str(self.__data__)
        string = string if len(string) < 13 else string[:12] + "..."
        return f"Payload<{string}>"

    __repr__ = __str__

    @property
    def data(self) -> bytes:
        return self.__data__

    @property
    def length(self) -> int:
        return len(self.__data__)

    def toBytes(self) -> bytes:
        """Serialize Payload object

        Returns:
            bytes: serialized object

        >>> Payload("Annie have a cat").toBytes()
        b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10Annie have a cat'
        """
        return struct.pack(SSIZE_T, len(self.__data__)) + self.__data__

    @staticmethod
    def fromBytesIO(source: BytesIO) -> "Payload":
        """Deserialize Payload object from BytesIO-like object

        Returns:
            Payload: deserialized payload object

        >>> Payload.fromBytesIO(BytesIO(b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10Annie have a cat'))
        Payload<b'Annie have...>
        """
        obj = Payload(
            source.read(
                struct.unpack(
                    SSIZE_T,
                    source.read(SIZEOF_SSIZE_T),
                )[0],
            )
        )
        LOG.debug(f"Deserialized Payload object {obj}")
        return obj


class Message:
    metadata: Metadata
    payload: Payload
    key: bytes

    def __init__(
        self,
        metadata: Metadata = None,
        payload: Payload = None,
        key: bytes = SHA256.new(b"").digest(),  # 32 bytes expected
    ) -> None:
        """Message wrapper object

        Args:
            metadata (Metadata, optional): message header. Defaults to None.
            payload (Payload, optional): message body. Defaults to None.
            key (bytes, optional): encryption key. Defaults to SHA256.new(b"").digest().
        """
        if isinstance(metadata, Metadata):
            self.metadata = metadata
        else:
            self.metadata = Metadata(metadata)
        if isinstance(payload, Payload):
            self.payload = payload
        else:
            self.payload = Payload(payload)
        self.key = key

    def __str__(self) -> str:
        """Stringify Message class

        Returns:
            str: string representation of Message class

        >>> Message({}, b"")
        Message<Metadata<{}>, Payload<b''>>
        """
        return f"Message<{self.metadata}, {self.payload}>"

    __repr__ = __str__

    def toBytes(self) -> bytes:
        """Serialize Message object for transportation

        Returns:
            bytes: serialized version of Message object

        >>> Message.fromBytesIO(BytesIO(Message({"key": "foo"}, b"123").toBytes()))
        Message<Metadata<{'key': 'foo...>, Payload<b'123'>>

        >>> key = SHA256.new(b"asfgSDFEWfDSAfw342").digest(); Message.fromBytesIO(BytesIO(Message({"key": "foo"}, b"123", key).toBytes()), key)
        Message<Metadata<{'key': 'foo...>, Payload<b'123'>>
        """
        raw = self.metadata.toBytes() + self.payload.toBytes()
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(raw)
        raw_cipher = cipher.nonce + tag + ciphertext
        raw_cipher_gzip = zlib.compress(raw_cipher)
        obj = struct.pack(SSIZE_T, len(raw_cipher_gzip)) + raw_cipher_gzip
        LOG.debug(f"Serialized Message object {obj[:18]}")
        return obj

    @staticmethod
    def fromBytesIO(
        source: BytesIO, key: Union[str, bytes] = SHA256.new(b"").digest()
    ) -> "Message":
        """Deserialize Message object

        Raises:
            RuntimeError: if object is not valid size

        Returns:
            Message: deserialized object

        >>> Message.fromBytesIO(BytesIO(Message({"key": "foo"}, b"123", SHA256.new(b"").digest()).toBytes()), SHA256.new(b"").digest())
        Message<Metadata<{'key': 'foo...>, Payload<b'123'>>

        >>> key = SHA256.new(b"asg534g5fgSDF354g534gEWfDSAfw342").digest(); Message.fromBytesIO(BytesIO(Message({"key": "foo"}, b"123", key).toBytes()), key)
        Message<Metadata<{'key': 'foo...>, Payload<b'123'>>
        """
        size = struct.unpack(SSIZE_T, source.read(SIZEOF_SSIZE_T))[0]
        buffer_ungzip = zlib.decompress(source.read(size))
        nonce = buffer_ungzip[:16]
        tag = buffer_ungzip[16:32]
        ciphertext = buffer_ungzip[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        buffer_decrypt = BytesIO(cipher.decrypt_and_verify(ciphertext, tag))
        obj = Message(
            Metadata.fromBytesIO(buffer_decrypt),
            Payload.fromBytesIO(buffer_decrypt),
            key,
        )
        LOG.debug(f"Deserialized Message object {obj}")
        return obj


class NetIO:

    socket: so.socket
    ip: str
    port: int
    key: bytes

    def __init__(
        self, socket: so.socket, ip: str, port: int, raw_key: Union[str, bytes]
    ) -> None:
        """socket.socket object wrapper providing Message communication

        Args:
            socket (so.socket): connected socket
            ip (str): socket ip
            port (int): socket port
            raw_key (Union[str, bytes]): encryption/autorization key

        >>> NetIO(None, "192.168.0.43", 8888, b"")
        NetIO<<class 'NoneType'>, 192.168.0.43:8888, e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855>

        >>> NetIO(None, "192.0.43", 8888, b"")
        Traceback (most recent call last):
            ...
        RuntimeError: Invalid IPv4 format: 192.0.43

        >>> NetIO(None, "192.168.0.43", 54, b"")
        Traceback (most recent call last):
            ...
        RuntimeError: Invalid port number, cannot exceed 1024 - 65535: 54
        """
        self.socket = socket
        if not (
            isinstance(ip, str)
            and re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip) is not None
            and all(0 <= int(x) <= 255 for x in ip.split("."))
        ):
            raise RuntimeError(f"Invalid IPv4 format: {ip}")
        self.ip = ip
        if not (isinstance(port, int) and 1024 <= port <= 65535):
            raise RuntimeError(
                f"Invalid port number, cannot exceed 1024 - 65535: {port}"
            )
        self.port = port
        self.key = SHA256.new(
            raw_key if isinstance(raw_key, bytes) else str(raw_key).encode("utf-8")
        ).digest()

    def __str__(self) -> str:
        """Stringify NetIO class

        Returns:
            str: string representation of NetIO class

        >>> NetIO(None, "192.168.0.43", 8888, b"")
        NetIO<<class 'NoneType'>, 192.168.0.43:8888, e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855>
        """
        return (
            f"NetIO<{self.socket.__class__}, {self.ip}:{self.port}, {self.key.hex()}>"
        )

    __repr__ = __str__

    def __del__(self) -> None:
        """Close associated socket"""
        try:
            self.socket.shutdown(so.SHUT_RDWR)
            self.socket.close()
            LOG.debug("Closed NetIO socket.")
        except Exception as e:
            LOG.debug(f"Failed to manually close NetIO socket: {e}")

    def read(self, number: int) -> bytes:
        """Read portion of bytes from associated socket,
        It will always either raise an exception or
        return block of expected size.

        Args:
            number (int): how many bytes to read

        Returns:
            bytes: raw bytes
        """
        _buffer = bytearray()
        while len(_buffer) != number:
            _buffer.extend(self.socket.recv(number - len(_buffer)))
        return bytes(_buffer)

    def recv(self) -> Message:
        """Receive message and return it as-is

        Returns:
            Message: message object
        """
        LOG.debug(f"Receiving object")
        obj = Message.fromBytesIO(self, self.key)
        LOG.debug(f"Received {obj}")
        return obj

    def recvM(self) -> Metadata:
        """Receive message, extract and return message header

        Returns:
            Metadata: message header object
        """
        LOG.debug(f"Receiving object")
        obj = Message.fromBytesIO(self, self.key)
        LOG.debug(f"Received {obj}")
        return obj.metadata

    def send(
        self, metadata: Dict[str, any] = None, payload: Union[str, bytes] = None
    ) -> None:
        """Send message object with custom metadata and payload

        Args:
            metadata (Dict[str, any], optional): message header. Defaults to None.
            payload (Union[str, bytes], optional): message body. Defaults to None.
        """
        message = Message(metadata, payload, self.key)
        LOG.debug(f"Sending {message}")
        self.socket.sendall(message.toBytes())
        LOG.debug(f"Sending finished")

    def sendM(self, **metakwargs: Any) -> None:
        """Send message object with custom metadata and empty body

        Kwrgs:
            metakwargs (Dict[str, any], optional): message header. Defaults to None.
        """
        message = Message(metakwargs, None, self.key)
        LOG.debug(f"Sending {message}")
        self.socket.sendall(message.toBytes())
        LOG.debug(f"Sending finished")

    @staticmethod
    def connect(
        ip: str,
        port: int,
        key: Union[str, bytes],
        *,
        timeout: float = None,
    ) -> "NetIO":

        LOG.info(f"Attemptin to connect to {ip}:{port}")
        # create socket
        socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        socket.settimeout(timeout)
        LOG.debug(f"Connecting to socket on {ip}:{port}")
        socket.connect((ip, port))
        LOG.debug(f"Created weak connection with {ip}:{port}")
        # create NetIO object
        socket = NetIO(socket, ip, port, key)
        # ensure connection
        if not ((meta := socket.recvM()) and meta["key"] == socket.key):
            socket.sendM(status="NOT_OK")
            raise ConnectionError("Client sent invalid connection key.")
        else:
            socket.sendM(status="OK")
            LOG.warning(f"Successfully connected to {ip}:{port}")
        return socket

    @staticmethod
    def accept(ip: str, port: int, key: bytes, *, timeout: float = None) -> "NetIO":
        """Create single NetIO object by creating listening server socket
        and waiting for incomeing connection which will be wrapped in NetIO
        object. Server socket will be closed after. Authentication with given
        key will be performed.

        Args:
            ip (str): server listening ip, 0.0.0.0 for any
            port (int): server port
            key (str): server authentication key
            timeout (float): server socket timeout

        Returns:
            NetIO: ready to use NetIO file
        """
        # create server socket IPv4 TCP
        socket = so.socket(so.AF_INET, so.SOCK_STREAM)
        socket.settimeout(30)
        socket.bind((ip, port))
        LOG.info(f"Opening socket on {ip}:{port}")
        socket.listen()
        client_socket, client_address = socket.accept()
        LOG.debug(f"Received connection from {client_address[0]}:{client_address[1]}")
        socket.close()
        client_socket.settimeout(timeout)
        # create NetIO object
        socket = NetIO(client_socket, *client_address, key)
        LOG.debug("Sending connection key")
        # ensutre connection safety
        socket.sendM(key=socket.key)
        if (meta := socket.recvM()) and meta["status"] == "OK":
            LOG.warning(
                f"Successfully accepted connection from {client_address[0]}:{client_address[1]}"
            )
        else:
            raise ConnectionError(
                f"Server refused connection key. Failed to connect to {client_address[0]}:{client_address[1]}"
            )
        return socket


def make_server(ip: str, port: int, key: str, timeout: float) -> Union[NetIO, None]:
    """Create single NetIO object by creating listening server socket
    and waiting for incomeing connection which will be wrapped in NetIO
    object. Server socket will be closed after. Authentication with given
    key will be performed.

    Args:
        ip (str): server listening ip, 0.0.0.0 for any
        port (int): server port
        key (str): server authentication key
        timeout (float): server socket timeout

    Returns:
        NetIO: ready to use NetIO file
        in case of exception
        None will be returned
    """
    LOG.info("Selected server mode, running NetIO server")
    try:
        connection = NetIO.accept(ip, port, key, timeout=timeout)
        return connection
    except so.timeout:
        LOG.fatal("Failed to estabilish connection due to timeout, closed NetIO server")
    except ConnectionError as e:
        LOG.fatal(f"Failed to estabilish connection due to an error: {e}")
    return None


def make_client(ip: str, port: int, key: str, timeout: float) -> Union[NetIO, None]:
    """Estabilish connection with server, return None in case of error. This function
    doesnt throw connection exceptions.

    Args:
        ip (str): server ip
        port (int): server port
        key (str): authentication key
        timeout (float): connection timeout

    Returns:
        Union[NetIO, None]: ready to use NetIO if succedeed, None otherwise
    """
    LOG.info("Selected client mode, connecting to NetIO server")
    try:
        connection = NetIO.connect(ip, port, key, timeout=timeout)
        return connection
    except so.timeout:
        LOG.fatal("Failed to estabilish connection due to timeout, aborting")
    except ConnectionRefusedError as e:
        LOG.fatal(f"Failed to estabilish connection, server refused connection: {e}")
    return None


if __name__ == "__main__":
    import argparse

    def parseArgv(src: List[str]) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        parser.add_argument("program", type=str, help="Python script path")
        parser.add_argument("ip", type=str, help="Connection IPv4")
        parser.add_argument("port", type=int, help="Connection port")
        parser.add_argument("key", type=str, help="Connection key")
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--test",
            "-t",
            action="store_true",
            default=False,
            help="Run doctests and exit",
        )
        group.add_argument(
            "--server",
            "-s",
            action="store_true",
            default=False,
            help="Run script as a server",
        )
        group.add_argument(
            "--client",
            "-c",
            action="store_true",
            default=False,
            help="Run script as a client",
        )
        parser.add_argument(
            "--loglvl",
            choices=("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"),
            default="WARNING",
            help="Logging level",
        )
        parser.add_argument(
            "--timeout", default=10, type=int, help="Client/Server connection timeout"
        )
        return parser.parse_args(src)

    argv = parseArgv(sys.argv)
    LOG.setLevel(argv.loglvl)
    LOG.debug(f"Arguments received: {argv}")
    if argv.test:
        LOG.debug("Selected doctest mode, running doctests")
        import doctest

        doctest.testmod(verbose=argv.loglvl == "DEBUG")
    elif argv.server:
        make_server(argv.ip, argv.port, argv.key, argv.timeout)
    elif argv.client:
        make_client(argv.ip, argv.port, argv.key, argv.timeout)
    else:
        exit(-1)
