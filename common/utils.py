from datetime import timedelta, datetime


def enforce_len(data: bytes, length: int) -> bytes:
    """Ensure the byte string is exactly 'length' bytes long."""
    return data[:length].ljust(length, b'\0')


def ts_to_bytes_with_ttl(timestamp: datetime, ttl_seconds: int) -> bytes:
    """
    Takes in an initial timestamp and a ttl to add to that timestamp (in
    seconds). Returns the binary representation of the joined timestamp.
    @param timestamp: An initial timestamp.
    @param ttl_seconds: A TTL to add to the initial timestamp.
    @return: A byte string representation for the joined timestamp.
    """
    expiration_time = timestamp + timedelta(seconds=ttl_seconds)
    expiration_timestamp = int(expiration_time.timestamp())
    return expiration_timestamp.to_bytes(8, byteorder='big')


def convert_bytes_to_timestamp(bytes_rep: bytes) -> datetime:
    """
    Receives a "bytes representation" of a timestamp and return a datetime
    from that value.
    @param bytes_rep: A representation (in bytes) for a timestamp.
    @return: An instantiated datetime object.
    """
    timestamp = int.from_bytes(bytes_rep, byteorder='big')
    return datetime.fromtimestamp(timestamp)
