import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


START = 0
END = 1
DATA = 2
ACK = 3

HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472


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


def _send_ack(sock, address, seq_num):
    sock.sendto(_make_packet(ACK, seq_num), address)


def receiver(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("window_size must be a positive integer")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    active_peer = None
    next_expected = 1
    buffered = {}

    try:
        while True:
            datagram, address = sock.recvfrom(65535)
            decoded = _decode_packet(datagram)
            if decoded is None:
                continue

            header, payload = decoded

            if header.type == START:
                if active_peer is not None:
                    continue
                if header.seq_num != 0 or header.length != 0:
                    continue

                active_peer = address
                next_expected = 1
                buffered.clear()
                _send_ack(sock, active_peer, 1)
                continue

            if active_peer is None or address != active_peer:
                continue

            if header.type == DATA:
                seq_num = header.seq_num
                if seq_num >= next_expected + window_size:
                    continue

                if seq_num >= next_expected:
                    buffered.setdefault(seq_num, payload)
                    if seq_num == next_expected:
                        while next_expected in buffered:
                            sys.stdout.buffer.write(buffered.pop(next_expected))
                            next_expected += 1
                        sys.stdout.buffer.flush()

                _send_ack(sock, active_peer, seq_num)
                continue

            if header.type == END:
                if header.length != 0:
                    continue
                if header.seq_num == next_expected:
                    _send_ack(sock, active_peer, header.seq_num + 1)
                    return
                _send_ack(sock, active_peer, next_expected)
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
    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
