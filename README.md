# Hazelcast 4+ member protocol dissector for WireShark

![Screenshot](imgs/hazelcast-dissector-screenshot.png)

## Installation

### Linux (Ubuntu) binaries

* download [hazelcast.so](https://github.com/hazelcast/hazelcast-dissector-for-wireshark/releases/download/latest-snapshot/hazelcast.so) library from the [latest-snapshot release tag](https://github.com/hazelcast/hazelcast-dissector-for-wireshark/releases/tag/latest-snapshot);
* copy the binary into `${HOME}/.local/lib/wireshark/plugins/3.2/epan/hazelcast.so`

```bash
mkdir -p "${HOME}/.local/lib/wireshark/plugins/3.2/epan/"
pushd "${HOME}/.local/lib/wireshark/plugins/3.2/epan/"
wget https://github.com/hazelcast/hazelcast-dissector-for-wireshark/releases/download/latest-snapshot/hazelcast.so
popd
```

### Other systems

We currently don't compile binaries for other platforms, but we welcome PRs that would handle such builds.

Look at [release-latest-snapshot-linux.yaml](.github/workflows/release-latest-snapshot-linux.yaml) GitHub workflow to learn how the Linux build is done.

## What's dissected

### Protocol header

Just 3 bytes: `HZC`

### Member packet

![Packet](imgs/packet.png)

### HeapData (payload)

![HeapData](imgs/heapdata.png)

### Serialized DataSerializable

```
Type (Serialization format) = -2
IDS flag=0
````

![DataSerializable](imgs/dataserializable.png)

### Serialized IdentifiedDataSerializable

```
Type (Serialization format) = -2
IDS flag=1
````

![IdentifiedDataSerializable](imgs/identifieddataserializable.png)

## Others

*For building whole Wireshark from sources take a look at https://gist.github.com/syneart/2d30c075c140624b1e150c8ea318a978*

### Generate packet layout images

```bash
sudo pip3 install nwdiag
cd imgs
for i in *.diag; do packetdiag $i; done
```
