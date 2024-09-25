package util

import "strings"

// 获取最后一个"/"前的字符串
func DefaultClsGetter(cls string) string {
	elem := strings.Split(cls, "/")
	return strings.Join(elem[:len(elem)-1], "/")
}

// 获取倒数第二个一个"/"前的字符串
func SecondClsGetter(cls string) string {
	elem := strings.Split(cls, "/")
	return strings.Join(elem[:len(elem)-2], "/")
}
