const NS_PER_SEC = Math.pow(10, 9);

const os         = require("os");
const raw        = require("raw-socket");
const types      = require("./types");

exports.ping = (options, next = noop) => {
	let packet = exports.build(options);

	var socket = raw.createSocket ({protocol: raw.Protocol.None, addressFamily: raw.AddressFamily.Raw});

	socket.on ("error", function (error) {
		next(error)
		socket.close ();
	});

	socket.send (packet, 0, packet.length, options.dev, function (error, bytes) {
		next(error)
		socket.close ();
	});
};

/**
 * Build an ARP packet. You can change properties from the packet
 * but you have to at least provide the target address
 *
 * Available options:
 *
 * - htype: hardware type               (default = Ethernet)
 * - sha: source hardware address       (default = runtime lookup)
 * - tha: target hardware address       (default = none)
 * - ptype: protocol type               (default = IPv4)
 * - spa: source protocol address       (default = runtime lookup)
 * - tpa: target protocol address       (default = none)
 * - operation: request or response     (default = request)
 * - dev: ethernet device to use        (default = first valid)
 *
 * @param   options                     Object with packet properties
 **/
exports.build = (options) => {
	if (typeof options.htype == "undefined")  options.htype = types.Ethernet;
	if (typeof options.ptype == "undefined")  options.ptype = types.IPv4;

	let offset = 14;
	let buffer = Buffer.alloc(offset + 8 + (options.htype.length * 2) + (options.ptype.length * 2));
	let iface  = null;

	buffer[0] = 0xFF;
	buffer[1] = 0xFF;
	buffer[2] = 0xFF;
	buffer[3] = 0xFF;
	buffer[4] = 0xFF;
	buffer[5] = 0xFF;

	buffer.writeUInt16BE(0x0806,               offset - 2); // ARP

	buffer.writeUInt16BE(options.htype.id,     offset + 0);
	buffer.writeUInt16BE(options.ptype.id,     offset + 2);
	buffer.writeUInt8   (options.htype.length, offset + 4);
	buffer.writeUInt8   (options.ptype.length, offset + 5);

	let operation = options.operation === undefined ? 0x0001 : options.operation
	buffer.writeUInt16BE(operation,            offset + 6); // Request

	offset += 8;

	if (typeof options.sha == "undefined" || typeof options.spa == "undefined") {
		let ifaces = os.networkInterfaces();

		for (let dev in ifaces) {
			if(options.dev && dev != options.dev) continue
			for (let i = 0; i < ifaces[dev].length; i++) {
				if (ifaces[dev][i].family != options.ptype.family) continue;

				if (typeof options.sha == "undefined" && typeof options.spa == "undefined") {
					if (ifaces[dev][i].internal) continue;
				} else if (typeof options.sha == "undefined") {
					if (ifaces[dev][i][options.ptype.interface_key] != options.spa) continue;
				} else if (typeof options.spa == "undefined") {
					if (ifaces[dev][i][options.htype.interface_key] != options.sha) continue;
				}

				iface = ifaces[dev][i];
				break;
			}

			if (iface !== null) break;
		}

		if (iface === null) throw new Error("Cannot find a suitable interface");

		buffer.writeUIntBE(options.htype.toNumber(iface[options.htype.interface_key]), 6, 6);

		buffer.writeUIntBE(options.htype.toNumber(iface[options.htype.interface_key]), offset, options.htype.length);
		offset += options.htype.length;

		buffer.writeUIntBE(options.ptype.toNumber(iface[options.ptype.interface_key]), offset, options.ptype.length);
		offset += options.ptype.length;
	} else {
		buffer.writeUIntBE(options.htype.toNumber(options.sha), 6, 6);

		buffer.writeUIntBE(options.htype.toNumber(options.sha), offset, options.htype.length);
		offset += options.htype.length;

		buffer.writeUIntBE(options.ptype.toNumber(options.spa), offset, options.ptype.length);
		offset += options.ptype.length;
	}

	if (typeof options.tha != "undefined") {
		buffer.writeUIntBE(options.htype.toNumber(options.tha), offset, options.htype.length);
	}
	offset += options.htype.length;

	if (typeof options.tpa != "undefined") {
		buffer.writeUIntBE(options.ptype.toNumber(options.tpa), offset, options.ptype.length);
	}
	offset += options.ptype.length;;

	return buffer;
};

function noop() {}
