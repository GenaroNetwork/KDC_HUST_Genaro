package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"reflect"
)

//  parse json file and save key-values into map (cannot handle array object)
func ParseJson(path string) (kvs map[string]string, num int, err error) {
	num = 0
	buff, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, num, err
	}

	var str map[string]interface{}
	err = json.Unmarshal(buff, &str)
	if err != nil {
		return nil, num, err
	}

	// save key-values into map
	kvs = make(map[string]string)
	TransformMap("", str, kvs, &num)
	return kvs, num, nil
}

func TransformMap(prefix string, in map[string]interface{}, out map[string]string, num *int) {
	for key, value := range in {
		if reflect.TypeOf(value) == reflect.TypeOf(in) {
			if prefix != "" {
				nprefix := prefix + "." + key
				TransformMap(nprefix, value.(map[string]interface{}), out, num)
			} else {
				TransformMap(key, value.(map[string]interface{}), out, num)
			}
		} else {
			if prefix != "" {
				nkey := prefix + "." + key
				out[nkey] = value.(string)
			} else {
				out[key] = value.(string)
			}
			*num++
		}
	}
}

// Print all key-values of json file (cannot handle array object)
func PrintJson(path string) {
	buff, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	// Unmarshal json string
	var str map[string]interface{}
	err = json.Unmarshal(buff, &str)
	if err != nil {
		panic(err)
	}

	TraverseMap(str)
}

func TraverseMap(in map[string]interface{}) {
	for key, _ := range in {
		if reflect.TypeOf(in[key]) == reflect.TypeOf(in) {
			TraverseMap(in[key].(map[string]interface{}))
		} else {
			fmt.Println(key, in[key])
		}
	}
}
