package main

import (
    "fmt"
    "time"
    "pcap"
    "encoding/hex"
)

func main() {
	pcapFile := os.Args[1]

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
    hex_string := hex.DecodeString("e765c87b4e3018082bfd3956e2ae1ebece1553f5b84100e892f3ad4ea959a58a90e78f69b32b92eab3fe46da21d2a08f98783f926cf82786b31fee727ef1e94728e3a2c74ac9c6b9bd401443d3a29b74a18b96edb78a5367223033832ca05dc9729dd210d84dffdaf4ee7b5e0e3f56fb")
    str := string(hex_string)

    target, _ := time.Parse("15:04:05.000000000", "12:38:13.489147000")
    start := target.Add(-time.Minute) // start an hour before the target time

    for current := start; current.Before(target); current = current.Add(time.Second) {
        fmt.Println(current.Format("15:04:05"))
    }
}