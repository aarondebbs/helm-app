// Command mkwinres writes the Windows resources (application manifest and version
// information) of the agent as COFF .syso objects that "go build" links automatically.
// Binaries that carry a proper manifest and version block are treated far less
// suspiciously by antivirus heuristics than anonymous executables.
//
//	go run ./tools/mkwinres -version 0.4.0 -out cmd/helm-agent
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"
)

const manifestXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Helm.Agent" version="%s" processorArchitecture="*"/>
  <description>Helm management agent</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings><longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware></windowsSettings>
  </application>
</assembly>
`

func u16(s string) []byte {
	var b bytes.Buffer
	for _, c := range utf16.Encode([]rune(s)) {
		binary.Write(&b, binary.LittleEndian, c)
	}
	return b.Bytes()
}

func pad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

// verBlock writes one VS_VERSIONINFO child: header, key, padding, value, then children.
func verBlock(key string, valueLen int, typ uint16, value []byte, children ...[]byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, uint16(valueLen), typ})
	b.Write(u16(key))
	b.Write([]byte{0, 0})
	pad4(&b)
	b.Write(value)
	for _, c := range children {
		pad4(&b)
		b.Write(c)
	}
	out := b.Bytes()
	binary.LittleEndian.PutUint16(out[0:], uint16(len(out)))
	return out
}

func versionInfo(version string) []byte {
	parts := [4]uint16{}
	for i, p := range strings.SplitN(version, ".", 4) {
		n, _ := strconv.Atoi(p)
		parts[i] = uint16(n)
	}
	var fixed bytes.Buffer
	ms, ls := uint32(parts[0])<<16|uint32(parts[1]), uint32(parts[2])<<16|uint32(parts[3])
	binary.Write(&fixed, binary.LittleEndian, []uint32{0xFEEF04BD, 0x10000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 1, 0, 0, 0})
	str := func(k, v string) []byte {
		return verBlock(k, len(u16(v))/2+1, 1, append(u16(v), 0, 0))
	}
	fields := [][2]string{{"CompanyName", "Helm"}, {"FileDescription", "Helm management agent"}, {"FileVersion", version},
		{"InternalName", "helm-agent"}, {"LegalCopyright", "Helm"}, {"OriginalFilename", "helm-agent.exe"},
		{"ProductName", "Helm"}, {"ProductVersion", version}}
	var kids [][]byte
	for _, f := range fields {
		k := str(f[0], f[1])
		for len(k)%4 != 0 {
			k = append(k, 0)
		}
		kids = append(kids, k)
	}
	table := verBlock("040904B0", 0, 1, nil, kids...)
	sfi := verBlock("StringFileInfo", 0, 1, nil, table)
	var tr bytes.Buffer
	binary.Write(&tr, binary.LittleEndian, uint32(0x04B00409))
	vfi := verBlock("VarFileInfo", 0, 1, nil, verBlock("Translation", 4, 0, tr.Bytes()))
	return verBlock("VS_VERSION_INFO", 52, 0, fixed.Bytes(), sfi, vfi)
}

// buildRsrc lays out the resource tree and returns the section bytes and the offsets of the
// two OffsetToData fields that need relocations.
func buildRsrc(blobs map[uint32][]byte) ([]byte, []uint32) {
	types := []uint32{16, 24} // RT_VERSION, RT_MANIFEST (ascending)
	var b bytes.Buffer
	w := func(v ...uint32) { binary.Write(&b, binary.LittleEndian, v) }
	dir := func(n uint16) {
		w(0, 0)
		binary.Write(&b, binary.LittleEndian, [3]uint16{0, 0, 0}) // major, minor, named
		binary.Write(&b, binary.LittleEndian, n)
	}
	// root
	dir(2)
	rootAt := 16
	_ = rootAt
	nameDirAt := func(i int) uint32 { return uint32(32 + i*48) }
	langDirAt := func(i int) uint32 { return nameDirAt(i) + 24 }
	for i, t := range types {
		w(t, 0x80000000|nameDirAt(i))
	}
	for i := range types {
		dir(1)
		w(1, 0x80000000|langDirAt(i))
		dir(1)
		w(0x409, 128+uint32(i)*16)
	}
	var relocs []uint32
	off := uint32(160)
	var data bytes.Buffer
	for i, t := range types {
		blob := blobs[t]
		relocs = append(relocs, uint32(128+i*16))
		w(off+uint32(data.Len()), uint32(len(blob)), 0, 0)
		data.Write(blob)
		for data.Len()%4 != 0 {
			data.WriteByte(0)
		}
	}
	b.Write(data.Bytes())
	return b.Bytes(), relocs
}

func coff(machine, relocType uint16, rsrc []byte, relocs []uint32) []byte {
	var b bytes.Buffer
	le := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	rawOff := uint32(20 + 40)
	relOff := rawOff + uint32(len(rsrc))
	symOff := relOff + uint32(len(relocs))*10
	le(machine)
	le(uint16(1))
	le(uint32(0))
	le(symOff)
	le(uint32(2)) // section symbol + aux
	le(uint16(0))
	le(uint16(0))
	b.Write([]byte(".rsrc\x00\x00\x00"))
	le(uint32(0))
	le(uint32(0))
	le(uint32(len(rsrc)))
	le(rawOff)
	le(relOff)
	le(uint32(0))
	le(uint16(len(relocs)))
	le(uint16(0))
	le(uint32(0x40000040))
	b.Write(rsrc)
	for _, r := range relocs {
		le(r)
		le(uint32(0)) // symbol 0 = the .rsrc section symbol
		le(relocType)
	}
	b.Write([]byte(".rsrc\x00\x00\x00"))
	le(uint32(0))
	le(int16(1))
	le(uint16(0))
	le(uint8(3))
	le(uint8(1))
	le(uint32(len(rsrc)))
	le(uint16(len(relocs)))
	le(uint16(0))
	le(uint32(0))
	le(uint16(0))
	le(uint8(0))
	b.Write([]byte{0, 0, 0})
	le(uint32(4)) // empty string table
	return b.Bytes()
}

func main() {
	version := flag.String("version", "0.0.0", "agent version")
	out := flag.String("out", ".", "directory to write the .syso files to")
	flag.Parse()
	v := strings.TrimPrefix(*version, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	for len(strings.Split(v, ".")) < 4 {
		v += ".0"
	}
	blobs := map[uint32][]byte{16: versionInfo(v), 24: []byte(fmt.Sprintf(manifestXML, v))}
	rsrc, relocs := buildRsrc(blobs)
	for _, t := range []struct {
		arch    string
		machine uint16
		reloc   uint16
	}{{"amd64", 0x8664, 3}, {"arm64", 0xAA64, 2}} {
		p := filepath.Join(*out, "resource_windows_"+t.arch+".syso")
		if err := os.WriteFile(p, coff(t.machine, t.reloc, rsrc, relocs), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
