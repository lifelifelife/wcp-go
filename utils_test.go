package wcp

import (
	"testing"
	"time"
)

func Test_condition(t *testing.T) {

	var cond = NewCondition()
	t.Log("begin")
	go func(){
		t.Log("waiting")
		cond.wait()
		t.Log("weaken from wait")
	}()

	go func() {
		time.Sleep( time.Duration(10*time.Second) )
		t.Log("send signal")
		cond.notify()
		t.Log("finish send signal")
	}()


	time.Sleep( time.Duration(15*time.Second))
}