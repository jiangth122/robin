package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/jiangth122/robin"
)

func main() {
	file1 := flag.String("f1", "", "src file")
	file2 := flag.String("f2", "", "dst file")
	flag.Parse()

	f1, err := os.Open(*file1)
	if err != nil {
		fmt.Println(err)
		return
	}
	f2, err := os.Open(*file2)
	if err != nil {
		fmt.Println(err)
		return
	}
	buf1, err := ioutil.ReadAll(f1)
	r := &robin.RobinFinger{}
	r.Init(3, 512, 2048, 1024, 31)
	p1, _ := r.Sharding(buf1)
	var num int
	fmt.Println("p1 info:")
	r.ShardingWithHandle(f2, func(data []byte, checksum int64, key string) error {
		fmt.Println("idx:", num, "key:", key, "checksum:", checksum, "len:", len(data))
		num++
		return nil
	})
	//p2, err := r.Sharding(buf2)

	report := func(r *robin.RobinFingerInfo) {
		i := 0
		r.Range(func(data []byte, checksum int64, key string) error {
			fmt.Println("idx:", i, "key:", key, "checksum:", checksum, "len:", len(data))
			//fmt.Println("context:", string(data))
			i++
			return nil
		})
	}
	fmt.Println("p2 info:")
	report(p1)
}
