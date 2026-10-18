"""
Hashicorp Yamux (Yet Another Multiplexer) Protocol Implementation in Pure Python.
Fully implements Yamux v0 specification (framing, flow control, window updates, ping/keepalive).
Supports both Client (odd stream IDs) and Server (even stream IDs) modes.
"""

import asyncio
import logging
import struct
from typing import Dict, Optional, Tuple

logger = logging.getLogger("packetstream.yamux")

# Protocol Constants
YAMUX_VERSION = 0

# Message Types
TYPE_DATA = 0x0
TYPE_WINDOW_UPDATE = 0x1
TYPE_PING = 0x2
TYPE_GO_AWAY = 0x3

# Flags
FLAG_SYN = 0x1
FLAG_ACK = 0x2
FLAG_FIN = 0x4
FLAG_RST = 0x8

# GoAway Reason Codes
GO_AWAY_NORMAL = 0x0
GO_AWAY_PROTO_ERR = 0x1
GO_AWAY_INTERNAL_ERR = 0x2

# Flow Control & Buffering
INITIAL_STREAM_WINDOW = 256 * 1024  # 256 KB default in Hashicorp Yamux
MAX_PAYLOAD_SIZE = 64 * 1024        # 64 KB per data frame chunk
HEADER_STRUCT = struct.Struct(">BBHII")  # version, type, flags, stream_id, length
HEADER_SIZE = 12


class YamuxError(Exception):
    """Base exception for Yamux errors."""
    pass


class YamuxStream:
    """
    Represents a single multiplexed stream within a Yamux session.
    Provides standard async read/write stream interface.
    """
    def __init__(self, session: "YamuxSession", stream_id: int):
        self.session = session
        self.stream_id = stream_id

        # Flow control windows
        self.send_window = INITIAL_STREAM_WINDOW
        self.recv_window = INITIAL_STREAM_WINDOW
        self._window_cond = asyncio.Condition()

        # Inbound data queue
        self._recv_buf = bytearray()
        self._data_event = asyncio.Event()

        # Stream states
        self.read_closed = False
        self.write_closed = False
        self.reset_occurred = False
        self._lock = asyncio.Lock()

    async def read(self, n: int = -1) -> bytes:
        """
        Reads up to n bytes from the stream buffer.
        Returns b"" on EOF (peer closed stream with FIN).
        """
        while True:
            if self._recv_buf:
                if n <= 0 or len(self._recv_buf) <= n:
                    data = bytes(self._recv_buf)
                    self._recv_buf.clear()
                else:
                    data = bytes(self._recv_buf[:n])
                    del self._recv_buf[:n]

                if not self._recv_buf:
                    self._data_event.clear()

                # Flow control: check if we need to replenish receive window
                await self._check_replenish_recv_window(len(data))
                return data

            if self.read_closed or self.reset_occurred:
                return b""

            # Wait for data or state change
            await self._data_event.wait()

    async def readexactly(self, n: int) -> bytes:
        """Reads exactly n bytes from the stream."""
        result = bytearray()
        while len(result) < n:
            chunk = await self.read(n - len(result))
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(result), n)
            result.extend(chunk)
        return bytes(result)

    async def readline(self) -> bytes:
        """Reads until newline \n is encountered or EOF."""
        result = bytearray()
        while True:
            idx = self._recv_buf.find(b"\n")
            if idx != -1:
                # Found newline in current buffer
                line = bytes(self._recv_buf[: idx + 1])
                del self._recv_buf[: idx + 1]
                if not self._recv_buf:
                    self._data_event.clear()
                await self._check_replenish_recv_window(len(line))
                result.extend(line)
                return bytes(result)

            if self._recv_buf:
                data = bytes(self._recv_buf)
                self._recv_buf.clear()
                self._data_event.clear()
                await self._check_replenish_recv_window(len(data))
                result.extend(data)

            if self.read_closed or self.reset_occurred:
                return bytes(result)

            await self._data_event.wait()

    async def _check_replenish_recv_window(self, bytes_consumed: int) -> None:
        """Replenishes receive window if it dropped below threshold."""
        self.recv_window -= bytes_consumed
        if self.recv_window <= (INITIAL_STREAM_WINDOW // 2) and not self.read_closed:
            delta = INITIAL_STREAM_WINDOW - self.recv_window
            self.recv_window += delta
            try:
                await self.session._send_window_update(self.stream_id, delta)
            except Exception as e:
                logger.debug(f"Stream {self.stream_id}: failed to send window update: {e}")

    async def write(self, data: bytes) -> None:
        """Writes data to the stream, handling chunking and flow control window."""
        if self.write_closed or self.reset_occurred:
            raise ConnectionResetError(f"Stream {self.stream_id} is closed for writing")

        offset = 0
        total = len(data)

        while offset < total:
            chunk_size = min(total - offset, MAX_PAYLOAD_SIZE)

            # Wait for send window to be available
            async with self._window_cond:
                while self.send_window <= 0 and not self.write_closed and not self.reset_occurred:
                    await self._window_cond.wait()

                if self.write_closed or self.reset_occurred:
                    raise ConnectionResetError(f"Stream {self.stream_id} closed during write")

                allowed = min(chunk_size, self.send_window)
                self.send_window -= allowed

            chunk = data[offset : offset + allowed]
            await self.session._send_data(self.stream_id, chunk)
            offset += allowed

    async def close(self) -> None:
        """Closes the write side of the stream by sending a FIN frame."""
        async with self._lock:
            if not self.write_closed:
                self.write_closed = True
                try:
                    await self.session._send_frame(TYPE_DATA, FLAG_FIN, self.stream_id, 0)
                except Exception:
                    pass
                async with self._window_cond:
                    self._window_cond.notify_all()
                self._maybe_remove_from_session()

    async def reset(self) -> None:
        """Resets the stream immediately by sending an RST frame."""
        async with self._lock:
            if not self.reset_occurred:
                self.reset_occurred = True
                self.read_closed = True
                self.write_closed = True
                try:
                    await self.session._send_frame(TYPE_DATA, FLAG_RST, self.stream_id, 0)
                except Exception:
                    pass
                self._data_event.set()
                async with self._window_cond:
                    self._window_cond.notify_all()
                self.session._remove_stream(self.stream_id)

    def _push_data(self, data: bytes) -> None:
        """Called by session when new data frame arrives for this stream."""
        if not self.read_closed and not self.reset_occurred:
            self._recv_buf.extend(data)
            self._data_event.set()

    def _push_window_update(self, delta: int) -> None:
        """Called by session when WINDOW_UPDATE arrives for this stream."""
        self.send_window += delta
        self._window_cond.notify_all()

    def _on_remote_fin(self) -> None:
        """Called by session when remote peer sent FIN."""
        self.read_closed = True
        self._data_event.set()
        self._maybe_remove_from_session()

    def _on_remote_rst(self) -> None:
        """Called by session when remote peer sent RST."""
        self.reset_occurred = True
        self.read_closed = True
        self.write_closed = True
        self._data_event.set()
        self._window_cond.notify_all()
        self.session._remove_stream(self.stream_id)

    def _maybe_remove_from_session(self) -> None:
        if self.read_closed and self.write_closed:
            self.session._remove_stream(self.stream_id)


class YamuxSession:
    """
    Manages a Yamux session over an asyncio StreamReader/StreamWriter pair.
    Can act as Yamux Server (exit node role) or Yamux Client.
    """
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        is_server: bool = True,
        keepalive_interval: float = 30.0
    ):
        self.reader = reader
        self.writer = writer
        self.is_server = is_server
        self.keepalive_interval = keepalive_interval

        # Client uses odd IDs (1, 3, 5...), Server uses even IDs (2, 4, 6...)
        self._next_stream_id = 2 if is_server else 1

        self._streams: Dict[int, YamuxStream] = {}
        self._accept_queue: asyncio.Queue[YamuxStream] = asyncio.Queue()

        self._write_lock = asyncio.Lock()
        self._closed = False
        self._close_event = asyncio.Event()

        # Ping state
        self._ping_seq = 0
        self._ping_futures: Dict[int, asyncio.Future[None]] = {}

        # Background tasks
        self._recv_task: Optional[asyncio.Task] = None
        self._keepalive_task: Optional[asyncio.Task] = None

    def start(self) -> None:
        """Starts background frame receiver and keepalive tasks."""
        loop = asyncio.get_running_loop()
        self._recv_task = loop.create_task(self._recv_loop())
        if self.keepalive_interval > 0:
            self._keepalive_task = loop.create_task(self._keepalive_loop())

    async def accept(self) -> YamuxStream:
        """Waits for and returns the next incoming stream opened by peer."""
        while not self._closed:
            accept_task = asyncio.create_task(self._accept_queue.get())
            close_task = asyncio.create_task(self._close_event.wait())
            done, pending = await asyncio.wait(
                [accept_task, close_task],
                return_when=asyncio.FIRST_COMPLETED
            )
            for t in pending:
                t.cancel()

            if accept_task in done:
                return accept_task.result()
            if close_task in done:
                break
        raise YamuxError("Yamux session is closed")

    async def open(self) -> YamuxStream:
        """
        Opens a new outbound stream to the remote peer (sends SYN flag).
        Used by exit node when sending token refresh.
        """
        if self._closed:
            raise YamuxError("Yamux session is closed")

        async with self._write_lock:
            stream_id = self._next_stream_id
            self._next_stream_id += 2

            stream = YamuxStream(self, stream_id)
            self._streams[stream_id] = stream

            # Send SYN frame
            await self._send_frame_locked(TYPE_DATA, FLAG_SYN, stream_id, 0)
            return stream

    async def ping(self, timeout: float = 10.0) -> None:
        """Sends a PING frame to remote peer and waits for ACK."""
        if self._closed:
            raise YamuxError("Yamux session is closed")

        loop = asyncio.get_running_loop()
        future: asyncio.Future[None] = loop.create_future()

        async with self._write_lock:
            self._ping_seq = (self._ping_seq + 1) & 0xFFFFFFFF
            seq = self._ping_seq
            self._ping_futures[seq] = future
            await self._send_frame_locked(TYPE_PING, 0, 0, seq)

        try:
            await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._ping_futures.pop(seq, None)

    async def close(self, reason: int = GO_AWAY_NORMAL) -> None:
        """Closes the Yamux session and underlying transport."""
        if self._closed:
            return
        self._closed = True
        self._close_event.set()

        # Send GO_AWAY frame
        try:
            async with self._write_lock:
                await self._send_frame_locked(TYPE_GO_AWAY, 0, 0, reason)
        except Exception:
            pass

        # Cancel background tasks
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()

        # Close all active streams
        for stream in list(self._streams.values()):
            await stream.reset()
        self._streams.clear()

        # Close underlying transport
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    async def _send_frame(self, msg_type: int, flags: int, stream_id: int, length: int) -> None:
        async with self._write_lock:
            await self._send_frame_locked(msg_type, flags, stream_id, length)

    async def _send_frame_locked(self, msg_type: int, flags: int, stream_id: int, length: int) -> None:
        hdr = HEADER_STRUCT.pack(YAMUX_VERSION, msg_type, flags, stream_id, length)
        self.writer.write(hdr)
        await self.writer.drain()

    async def _send_data(self, stream_id: int, data: bytes) -> None:
        async with self._write_lock:
            hdr = HEADER_STRUCT.pack(YAMUX_VERSION, TYPE_DATA, 0, stream_id, len(data))
            self.writer.write(hdr)
            self.writer.write(data)
            await self.writer.drain()

    async def _send_window_update(self, stream_id: int, delta: int) -> None:
        await self._send_frame(TYPE_WINDOW_UPDATE, 0, stream_id, delta)

    def _remove_stream(self, stream_id: int) -> None:
        self._streams.pop(stream_id, None)

    async def _keepalive_loop(self) -> None:
        """Sends periodic Yamux Ping to maintain connection and detect stale sessions."""
        try:
            while not self._closed:
                await asyncio.sleep(self.keepalive_interval)
                if self._closed:
                    break
                try:
                    await self.ping(timeout=10.0)
                except Exception as e:
                    logger.warning(f"Yamux keepalive ping failed: {e}")
                    await self.close(GO_AWAY_PROTO_ERR)
                    break
        except asyncio.CancelledError:
            pass

    async def _recv_loop(self) -> None:
        """Main receive loop processing 12-byte Yamux frame headers."""
        try:
            while not self._closed:
                header_bytes = await self.reader.readexactly(HEADER_SIZE)
                version, msg_type, flags, stream_id, length = HEADER_STRUCT.unpack(header_bytes)

                if version != YAMUX_VERSION:
                    logger.error(f"Unsupported Yamux version: {version}")
                    await self.close(GO_AWAY_PROTO_ERR)
                    break

                if msg_type == TYPE_DATA:
                    payload = b""
                    if length > 0:
                        payload = await self.reader.readexactly(length)
                    await self._handle_data_frame(stream_id, flags, payload)

                elif msg_type == TYPE_WINDOW_UPDATE:
                    await self._handle_window_update(stream_id, flags, length)

                elif msg_type == TYPE_PING:
                    await self._handle_ping(flags, length)

                elif msg_type == TYPE_GO_AWAY:
                    logger.info(f"Received Yamux GO_AWAY (code={length}) from peer")
                    await self.close(GO_AWAY_NORMAL)
                    break

                else:
                    logger.warning(f"Unknown Yamux message type: {msg_type}")
                    await self.close(GO_AWAY_PROTO_ERR)
                    break

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as e:
            logger.debug(f"Yamux underlying connection closed: {e}")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in Yamux receive loop: {e}", exc_info=True)
        finally:
            await self.close(GO_AWAY_NORMAL)

    async def _handle_data_frame(self, stream_id: int, flags: int, data: bytes) -> None:
        # Handle SYN (New Stream)
        stream = self._streams.get(stream_id)
        if flags & FLAG_SYN:
            if stream is None:
                stream = YamuxStream(self, stream_id)
                self._streams[stream_id] = stream
                await self._accept_queue.put(stream)
            # Send ACK if required by spec
            if not (flags & FLAG_ACK):
                try:
                    await self._send_frame(TYPE_DATA, FLAG_ACK, stream_id, 0)
                except Exception:
                    pass

        if stream is None:
            # Stream unknown, may have already been closed/reset
            if not (flags & FLAG_RST):
                try:
                    await self._send_frame(TYPE_DATA, FLAG_RST, stream_id, 0)
                except Exception:
                    pass
            return

        if flags & FLAG_RST:
            stream._on_remote_rst()
            return

        if data:
            stream._push_data(data)

        if flags & FLAG_FIN:
            stream._on_remote_fin()

    async def _handle_window_update(self, stream_id: int, flags: int, delta: int) -> None:
        stream = self._streams.get(stream_id)
        if flags & FLAG_SYN and stream is None:
            stream = YamuxStream(self, stream_id)
            self._streams[stream_id] = stream
            await self._accept_queue.put(stream)

        if stream is not None:
            async with stream._window_cond:
                stream._push_window_update(delta)

            if flags & FLAG_RST:
                stream._on_remote_rst()
            elif flags & FLAG_FIN:
                stream._on_remote_fin()

    async def _handle_ping(self, flags: int, seq: int) -> None:
        if flags & FLAG_ACK:
            # Acknowledgement of our ping
            fut = self._ping_futures.get(seq)
            if fut and not fut.done():
                fut.set_result(None)
        else:
            # Inbound ping from peer: reflect back with ACK
            try:
                await self._send_frame(TYPE_PING, FLAG_ACK, 0, seq)
            except Exception as e:
                logger.debug(f"Failed to respond to peer ping: {e}")
