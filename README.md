# Assumptions

1. I added to Code request 1025 (Server registration) 2 fields - `ip` & `port`.
   The ip is a 4 byte field whereas the port is a 2 bytes field. To 
   streamline the process I just hardcoded the ip to `0.0.0.0` on client 
   side and added a random selection of port between `1000-9999`.