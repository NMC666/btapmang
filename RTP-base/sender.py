import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


START = 0
END = 1
DATA = 2
ACK = 3

HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
RETRANSMIT_SECONDS = 0.5


def _make_packet(packet_type, seq_num, payload=b""):
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0,
    )
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)


def _decode_packet(datagram):
    if len(datagram) < HEADER_SIZE or len(datagram) > MAX_PACKET_SIZE:
        return None

    try:
        header = PacketHeader(datagram[:HEADER_SIZE])
        if header.length != len(datagram) - HEADER_SIZE:
            return None

        payload = datagram[HEADER_SIZE:]
        received_checksum = header.checksum
        header.checksum = 0
        if compute_checksum(header / payload) != received_checksum:
            return None
        return header, payload
    except (IndexError, TypeError, ValueError):
        return None


def _wait_for_ack(sock, expected_seq_num):
    while True:
        datagram, _ = sock.recvfrom(2048)
        decoded = _decode_packet(datagram)
        if decoded is None:
            continue

        header, _ = decoded
        if header.type == ACK and header.length == 0:
            if header.seq_num == expected_seq_num:
                return


def sender(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("window_size must be a positive integer")

    destination = (receiver_ip, receiver_port)
    message = sys.stdin.buffer.read()
    chunks = [
        message[offset : offset + MAX_PAYLOAD_SIZE]
        for offset in range(0, len(message), MAX_PAYLOAD_SIZE)
    ]
    packets = {
        seq_num: _make_packet(DATA, seq_num, chunk)
        for seq_num, chunk in enumerate(chunks, start=1)
    }
    packet_count = len(chunks)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(_make_packet(START, 0), destination)
        _wait_for_ack(sock, 1)

        base = 1
        next_seq_num = 1
        deadline = None

        while base <= packet_count:
            while (
                next_seq_num <= packet_count
                and next_seq_num < base + window_size
            ):
                sock.sendto(packets[next_seq_num], destination)
                next_seq_num += 1
                if deadline is None:
                    deadline = time.monotonic() + RETRANSMIT_SECONDS

            if base == next_seq_num:
                deadline = None
                continue

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                for seq_num in range(base, next_seq_num):
                    sock.sendto(packets[seq_num], destination)
                deadline = time.monotonic() + RETRANSMIT_SECONDS
                continue

            sock.settimeout(remaining)
            try:
                datagram, _ = sock.recvfrom(2048)
            except socket.timeout:
                for seq_num in range(base, next_seq_num):
                    sock.sendto(packets[seq_num], destination)
                deadline = time.monotonic() + RETRANSMIT_SECONDS
                continue

            decoded = _decode_packet(datagram)
            if decoded is None:
                continue

            header, _ = decoded
            if header.type != ACK or header.length != 0:
                continue

            if base < header.seq_num <= next_seq_num:
                base = header.seq_num
                if base < next_seq_num:
                    deadline = time.monotonic() + RETRANSMIT_SECONDS
                else:
                    deadline = None

        end_seq_num = packet_count + 1
        sock.sendto(_make_packet(END, end_seq_num), destination)

        end_deadline = time.monotonic() + RETRANSMIT_SECONDS
        while True:
            remaining = end_deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                datagram, _ = sock.recvfrom(2048)
            except socket.timeout:
                break

            decoded = _decode_packet(datagram)
            if decoded is None:
                continue
            header, _ = decoded
            if (
                header.type == ACK
                and header.length == 0
                and header.seq_num == end_seq_num + 1
            ):
                break
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()
    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
