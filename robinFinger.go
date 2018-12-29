//
//
package robin

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
)

type RobinFingerInfo struct {
	poly []polynomialInfo
}

type polynomialInfo struct {
	data          []byte
	robinChecksum int64
	key           string
}

type RobinFinger struct {
	min              int
	max              int
	avg              int
	win              int
	prime            int64
	polynomialFactor []int64
}

var (
	INVALID_ARGUMENT error = errors.New("Invalid argument")
)

func (r *RobinFingerInfo) Range(f func(data []byte, checksum int64, key string) error) error {
	for _, p := range r.poly {
		err := f(p.data, p.robinChecksum, p.key)
		if err != nil {
			return err
		}
	}

	return nil

}

func (r *RobinFingerInfo) Count() int {
	if r.poly == nil {
		return 0
	}

	return len(r.poly)
}

func (r *RobinFingerInfo) At(i int) ([]byte, int64, string, error) {
	if i >= len(r.poly) {
		return nil, 0, "", errors.New("out of oride")
	}

	return r.poly[i].data, r.poly[i].robinChecksum, r.poly[i].key, nil
}

func (r *RobinFingerInfo) Equal(idx int, checkSum int64, key string) bool {
	if idx >= len(r.poly) {
		return false
	}

	return r.poly[idx].robinChecksum == checkSum && r.poly[idx].key == key
}

// Init初始化RobinFinger
//
// 参数:
//     prime:切片概率点，推荐值3
//     min:切片最小块
//     max:切片最大块
//     avg:切片平均大小
//     win:切片窗口，推荐值31
func (r *RobinFinger) Init(prime, min, max, avg, win int) error {
	if min <= win {
		return INVALID_ARGUMENT
	}
	r.min = min
	r.max = max
	r.avg = avg
	r.win = win
	r.prime = int64(prime)
	r.polynomialFactor = make([]int64, r.win+1)
	for factor, i := int64(1), 0; i <= r.win; i++ {
		r.polynomialFactor[i] = factor
		factor *= int64(prime)
	}
	return nil
}

func (r *RobinFinger) genKey(buf []byte) string {
	_md5 := md5.New()
	_md5.Write(buf)
	cipherStr := _md5.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

// AppendSharding 往RobinFingerInfo添加一块切片
func (rfi *RobinFingerInfo) AppendSharding(buf []byte, checksum int64, key string) {
	if rfi.poly == nil {
		rfi.poly = make([]polynomialInfo, 0, 100)
	}
	rfi.poly = append(rfi.poly, polynomialInfo{
		data:          buf,
		robinChecksum: checksum,
		key:           key,
	})
}

// ShardingWithHandle 通过读取reader的数据进行数据切片，直到读取结束或者读取异常，
// 或者回调返回异常。每次切片完成后调用回调函数，注意回调中的data不能长时间持有，
// 回调函数完成后，该buf有可能会被重复使用，因此回调函数中需要直接处理完，如write
// 到网络或者文件，如果需要异步操作的话，则需要将数据拷贝走。
//
// 参数:
//      reader:数据来源，任意符合io.Reader均符合，若为buf，可以通过bufio.NewReader(buf)等
// 方式封装
//      f:回调函数，每块切片均会调用，若处理异常且不建议继续进行切片的话，请返回非nil
//
// 返回值:
//       error:reader读取非io.EOF的异常或者回调函数的异常将被返回，否则返回nil
func (r *RobinFinger) ShardingWithHandle(reader io.Reader, f func(data []byte, checksum int64, key string) error) error {
	offset := r.min - r.win
	s := bufio.NewScanner(reader)
	s.Split(func(b []byte, atEOF bool) (int, []byte, error) {
		sz := 0
	Next:
		if sz >= len(b) {
			return sz, nil, nil
		}
		tmpBuf := b[sz:]
		if offset+r.win > len(tmpBuf) {
			if atEOF {
				err := f(tmpBuf, 0, r.genKey(tmpBuf))
				return sz + len(tmpBuf), nil, err
			}

			return sz, nil, nil
		}

		if offset+r.win > r.max {
			err := f(tmpBuf[:r.max], 0, r.genKey(tmpBuf[:r.max]))
			sz += r.max
			offset = r.min - r.win
			if err != nil {
				return sz, nil, err
			}
			goto Next
		}

		var rollChecksum int64 = 0
		winData := tmpBuf[offset : offset+r.win]
		for i, v := range winData {
			rollChecksum += int64(v) * r.polynomialFactor[r.win-i]
		}

		if rollChecksum%int64(r.avg) == r.prime {
			err := f(tmpBuf[:offset+r.win], rollChecksum, r.genKey(tmpBuf[:offset+r.win]))
			sz += offset + r.win
			offset = r.min - r.win
			//sz += offset + r.win
			if err != nil {
				return sz, nil, err
			}
			goto Next
		}
		offset++
		goto Next

	})

	for s.Scan() {
	}

	return s.Err()
}

// Sharding 对给定的数据进行切片，并将切片完成后的数据计算md5及checksum
// 存储在RobinFingerInfo结构中。根据robin的切片算法，数据小于r.min的或者
// 数据大于r.max还无法计算出概率点的，将直接作为一个切片，此时checksum=0
//
// 参数:
//       src:需要切片的原始数据
// 返回值:
//       *RobinFingerInfo:用于存储切片信息，可以通过该结构的Range方法遍历切片，
// 也可以通过该结构的At方法获取指定切片。
//       error:目前该函数不会返回错误
func (r *RobinFinger) Sharding(src []byte) (*RobinFingerInfo, error) {
	rfi := &RobinFingerInfo{}
	appendSharding := func(buf []byte, checksum int64) {
		rfi.poly = append(rfi.poly, polynomialInfo{
			data:          buf,
			robinChecksum: checksum,
			key:           r.genKey(buf),
		})
	}

	if len(src) < r.min || r.min < r.win {
		appendSharding(src, 0)
		return rfi, nil
	}

	startPos := 0
	winStartPos := r.min - r.win
	for {
		if startPos >= len(src) {
			break
		}
		buf := src[startPos:]
		if winStartPos+r.win >= len(buf) {
			appendSharding(buf, 0)
			break
		}

		if winStartPos+r.win >= r.max {
			appendSharding(buf[:r.max], 0)
			startPos = startPos + r.max
			winStartPos = r.min - r.win
			continue
		}

		var rollChecksum int64 = 0
		winData := buf[winStartPos : winStartPos+r.win]
		for i, v := range winData {
			rollChecksum += int64(v) * r.polynomialFactor[r.win-i]
		}

		if rollChecksum%int64(r.avg) == r.prime {
			appendSharding(buf[:winStartPos+r.win], rollChecksum)
			startPos += winStartPos + r.win
			winStartPos = r.min - r.win
			continue
		}

		winStartPos++
	}

	return rfi, nil

}

/*
func (r *RobinFinger) Sharding(src []byte) (*RobinFingerInfo, error) {
	rfi := &RobinFingerInfo{}
	appendSharding := func(start, end int, checksum int64) {
		rfi.poly = append(rfi.poly, polynomialInfo{
			data:          src[start:end],
			robinChecksum: checksum,
			key:           r.genKey(src[start:end]),
		})
	}

	if len(src) < r.min || r.min < r.win {
		appendSharding(0, len(src), 0)
		return rfi, nil
	}

	startPos := 0
	winStartPos := r.min - r.win

	for {
		if winStartPos+r.win >= len(src) {
			if startPos < len(src) {
				appendSharding(startPos, len(src), 0)
			}
			break
		}

		if winStartPos+r.win-startPos >= r.max {
			appendSharding(startPos, startPos+r.max, 0)
			startPos = startPos + r.max
			winStartPos = startPos + r.min - r.win
			continue
		}

		var rollChecksum int64 = 0
		winData := src[winStartPos : winStartPos+r.win]
		for i, v := range winData {
			rollChecksum += int64(v) * r.polynomialFactor[r.win-i]
		}

		if rollChecksum%int64(r.avg) == r.prime {
			appendSharding(startPos, winStartPos+r.win, rollChecksum)
			startPos = winStartPos + r.win
			winStartPos = startPos + r.min - r.win
			continue
		}

		winStartPos++
	}

	return rfi, nil
}
*/
