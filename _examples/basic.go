package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/sozenh/zk"
)

var (
	serverAddr = flag.String("address", "127.0.0.1:2181", "zookeeper server address")
	username   = flag.String("username", "", "username")
	password   = flag.String("password", "", "password")
)

func ConnectZkExample() {
	c, _, err := zk.Connect([]string{*serverAddr}, time.Second)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	testPathPrefix := "/test"
	for i := 0; i < 10; i++ {
		fmt.Println("==============================================")
		testPath := fmt.Sprintf("%s-%05d", testPathPrefix, i)
		value := []byte(fmt.Sprintf("data-%05d", i))

		// check
		exist, stat, err := c.Exists(testPath)
		if err != nil {
			panic(fmt.Sprintf("check path %v exists failed", testPath))
		}

		// set
		if exist {
			_, err = c.Set(testPath, value, -1)
			if err != nil {
				panic(fmt.Sprintf("set value [%v] failed: %v", testPath, err))
			}
		} else {
			_, err = c.Create(testPath, value, 0, zk.WorldACL(zk.PermAll))
			if err != nil {
				panic(fmt.Sprintf("failed to create path %v, error: %v", testPath, err))
			}
		}

		// get
		value, stat, err = c.Get(testPath)
		if err != nil {
			panic(fmt.Sprintf("error: %v", err))
		}
		fmt.Printf("stat: [%+v]\n", stat)
		fmt.Printf("value: [%s]\n", string(value))
	}
}

func ConnectZkWithSaslExample() {
	fmt.Printf("connecting zookeeper with username: %v, password: %v\n", *username, *password)
	c, _, err := zk.Connect([]string{*serverAddr}, time.Second)
	if err != nil {
		panic(err)
	}
	defer c.Close()

	authData := fmt.Sprintf("%s:%s", *username, *password)
	fmt.Printf("auth data: %v\n", authData)
	_ = c.AddAuth("sasl", []byte(authData))

	testPathPrefix := "/test"
	for i := 0; i < 10; i++ {
		fmt.Println("==============================================")
		testPath := fmt.Sprintf("%s-%05d", testPathPrefix, i)
		value := []byte(fmt.Sprintf("data-%05d", i))

		// check
		exist, stat, err := c.Exists(testPath)
		if err != nil {
			panic(fmt.Sprintf("check path %v exists failed", testPath))
		}

		// set
		if exist {
			_, err = c.Set(testPath, value, -1)
			if err != nil {
				panic(fmt.Sprintf("set value [%v] failed: %v", testPath, err))
			}
		} else {
			_, err = c.Create(testPath, value, 0, zk.SaslACL(*username, zk.PermAll))
			if err != nil {
				panic(fmt.Sprintf("failed to create path %v, error: %v", testPath, err))
			}
		}

		// get
		value, stat, err = c.Get(testPath)
		if err != nil {
			panic(fmt.Sprintf("error: %v", err))
		}
		fmt.Printf("stat: [%+v]\n", stat)
		fmt.Printf("value: [%s]\n", string(value))
	}
}

func main() {
	flag.Parse()
	if len(*username) > 0 && len(*password) > 0 {
		// test connect zookeeper with sasl
		ConnectZkWithSaslExample()
	} else {
		// test connect zookeeper without sasl
		ConnectZkExample()
	}
}
