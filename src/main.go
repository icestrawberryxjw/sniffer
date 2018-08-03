package main
import (
	"fmt"
	"log"
	"time"
	"github.com/icestrawberryxjw/gopacket/afpacket"
	//"github.com/tsg/gopacket/pcap"
	//"github.com/tsg/gopacket/layers"
	"os"
	//"unsafe"
	//"github.com/google/gopacket"
	//"github.com/tsg/gopacket/afpacket"
	//"github.com/tsg/gopacket/pcapgo"
	//"github.com/google/gopacket/pcap"

	"github.com/icestrawberryxjw/gopacket/layers"
	"github.com/icestrawberryxjw/gopacket/pcap"
)

type afpacketHandle struct {
	TPacket *afpacket.TPacket
}

var (
	//device     string      = "em1"
	snapshot_len int           = 65535
	promiscuous  bool          = true
	timeout      time.Duration =  time.Millisecond*50
	//err        error
	//handle     *pcap.Handle
	buffersizeMb int           =500
)
func OpenAFpacket(nic string)( *afpacketHandle,error){

	handle := &afpacketHandle{}
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(buffersizeMb, snapshot_len, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("page size:",os.Getpagesize())
	fmt.Println("frame size:",szFrame)
	fmt.Println("block size:",szBlock)
	fmt.Println("num blocks:",numBlocks)
	fmt.Println("snaplen :",snapshot_len)
	//fmt.Println(unsafe.Sizeof(snapshot_len))

	handle.TPacket, err = afpacket.NewTPacket(
		afpacket.OptInterface(nic),
		afpacket.OptFrameSize(szFrame),
		afpacket.OptBlockSize(szBlock),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(timeout))
	return handle,err

}


func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Buffer size too small")
	}
	return frameSize, blockSize, numBlocks, nil
}

func main() {

	var dumper  *pcap.Dumper
	var packetnum int64
	h,err :=OpenAFpacket("wlp3s0")
	if err !=nil{
		log.Fatal(err)
	}
	////h.TpacketVersion()
	//f, _ := os.Create(config.PCAP_DIR+"/testcapture.pcap")
	//w := pcapgo.NewWriter(f)
	//w.WriteFileHeader(65536, layers.LinkTypeEthernet)  // new file, must do this

	dumper, err = openDumper("/home/testcapturexjw.pcap", layers.LinkTypeEthernet)
	if err != nil {
		return
	}

	defer dumper.Close()

	for{
		//fmt.Println(1)
		data,ci,err := h.TPacket.ZeroCopyReadPacketData()

		if err!=nil{
			if err==afpacket.ErrTimeout{
				//fmt.Println("timeout......")
				continue
			}
			log.Fatal(err)
		}
		//fmt.Println(data,ci)

		err =dumper.WritePacketData(data, ci)
		if err!=nil{
			log.Fatal(err)
		}
		//fmt.Println(2)

		//err=w.WritePacket(ci, data)
		//if err!=nil{
		//	log.Fatal(err)
		//}
		packetnum++
		fmt.Println("packet num",packetnum)
		//Stats, err :=h.Stats()
		//fmt.Println("state packet:",Stats.Packets)
		//fmt.Println("state poll:",Stats.Polls)
		if packetnum==10000{
			dumper.Flush()
			//return
		}
	}
	//defer fmt.Println("game over...")
}

func openDumper(file string, linkType layers.LinkType) (*pcap.Dumper, error) {
	p, err := pcap.OpenDead(linkType, 65535)
	if err != nil {
		return nil, err
	}

	return p.NewDumper(file)
}

