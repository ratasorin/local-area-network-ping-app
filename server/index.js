const cap = require("cap").Cap;
const os = require("os");

const CURRENT_DEVICE_IP = "192.168.0.4";
const MAC = Object.values(os.networkInterfaces())
  .reduce(
    (prev, current) => [
      ...prev,
      current.filter(({ address }) => address === CURRENT_DEVICE_IP)[0]?.mac,
    ],
    []
  )
  .filter((e) => e)[0]
  .split(":")
  .reduce((prev, curr) => [...prev, parseInt(curr, 16)], []);

const decoders = require("cap").decoders;
const PROTOCOL = decoders.PROTOCOL;
const FILTER = "arp net 192.168.0";

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

// prettier-ignore
const messageToBroadcast = Buffer.from([
    // ETHERNET
    0xff, 0xff, 0xff, 0xff, 0xff,0xff,                  // 0    = Destination MAC
    0x84, 0x8F, 0x69, 0xB7, 0x3D, 0x92,                 // 6    = Source MAC
    0x08, 0x06,                                         // 12   = EtherType = ARP
    // ARP
    0x00, 0x01,                                         // 14/0   = Hardware Type = Ethernet (or wifi)
    0x08, 0x00,                                         // 16/2   = Protocol type = ipv4 (request ipv4 route info)
    0x06, 0x04,                                         // 18/4   = Hardware Addr Len (Ether/MAC = 6), Protocol Addr Len (ipv4 = 4)
    0x00, 0x01,                                         // 20/6   = Operation (ARP, who-has)
    ...MAC,                                             // 22/8   = Sender Hardware Addr (MAC)
    0xc0, 0xa8, 0x01, 0xc8,                             // 28/14  = Sender Protocol address (ipv4)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                 // 32/18  = Target Hardware Address (Blank/nulls for who-has)
    0xc0, 0xa8, 0x01, 0xc9                              // 38/24  = Target Protocol address (ipv4)
]);

const sendMessage = () => {
  try {
    // send will not work if pcap_sendpacket is not supported by underlying `device`
    c.send(messageToBroadcast, messageToBroadcast.length);
  } catch (e) {
    console.log("Error sending packet:", e);
  }
};

const express = require("express");
const app = express();

app.get("/", function (req, res) {
  sendMessage();
});

app.listen(5000);
