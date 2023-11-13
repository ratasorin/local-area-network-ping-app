const CURRENT_DEVICE_IP = "192.168.0.4";
const cap = require("cap").Cap;
const decoders = require("cap").decoders;
const PROTOCOL = decoders.PROTOCOL;
const FILTER = "arp";

const c = new cap();
const device = cap.findDevice(CURRENT_DEVICE_IP);
const bufSize = 10 * 1024 * 1024;
const buffer = Buffer.alloc(65535);

const linkType = c.open(device, FILTER, bufSize, buffer);

c.setMinBytes && c.setMinBytes(0);

c.on("packet", function (bytes, trunc) {
  console.log(
    "packet: length " + bytes + " bytes, truncated? " + (trunc ? "yes" : "no")
  );

  if (linkType === "ETHERNET") {
    const ret = decoders.Ethernet(buffer);

    if (ret.info.type === PROTOCOL.ETHERNET.ARP) {
      console.log("Decoding ARP ...");
    } else {
      console.log("Unsupported Ethertype: " + PROTOCOL.ETHERNET[ret.info.type]);
    }
  }
});
